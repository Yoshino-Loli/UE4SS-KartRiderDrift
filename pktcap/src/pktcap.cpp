// pktcap.dll - 网络收发包录制
// hook ws2_32 的收发函数（含重叠 I/O），把原始字节落盘
//
// 记录格式（小端）:
//   [0]      char     方向 'S'=发送 'R'=接收
//   [1..4]   uint32   载荷长度
//   [5..12]  uint64   GetTickCount64 时间戳(ms)
//   [13..16] uint32   对端 IPv4
//   [17..18] uint16   对端端口
//   [19..]   bytes    载荷
// 文件头: "PKTCAP01" + uint32 版本(2)

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include "MinHook.h"

#pragma comment(lib, "ws2_32.lib")

static FILE*            g_file  = NULL;
static CRITICAL_SECTION g_cs;
static volatile LONG    g_count = 0;
static volatile LONG    g_bytes = 0;
static wchar_t          g_outdir[MAX_PATH] = {0};

// ---------- 重叠 I/O 追踪 ----------
#define MAX_OV   2048
#define MAX_BUFS 8
struct OvEntry {
    LPWSAOVERLAPPED  ov;
    char             dir;
    DWORD            cnt;
    WSABUF           bufs[MAX_BUFS];
    struct sockaddr* from;
    LPINT            fromlen;
};
static OvEntry          g_ov[MAX_OV];
static CRITICAL_SECTION g_ovcs;

// ---------- 原始函数 ----------
typedef int (WSAAPI *pfn_send)(SOCKET, const char*, int, int);
typedef int (WSAAPI *pfn_recv)(SOCKET, char*, int, int);
typedef int (WSAAPI *pfn_sendto)(SOCKET, const char*, int, int, const struct sockaddr*, int);
typedef int (WSAAPI *pfn_recvfrom)(SOCKET, char*, int, int, struct sockaddr*, int*);
typedef int (WSAAPI *pfn_WSASend)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI *pfn_WSARecv)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI *pfn_WSASendTo)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, const struct sockaddr*, int, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI *pfn_WSARecvFrom)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, struct sockaddr*, LPINT, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef BOOL (WSAAPI *pfn_WSAGetOverlappedResult)(SOCKET, LPWSAOVERLAPPED, LPDWORD, BOOL, LPDWORD);

static pfn_send                   o_send                   = NULL;
static pfn_recv                   o_recv                   = NULL;
static pfn_sendto                 o_sendto                 = NULL;
static pfn_recvfrom               o_recvfrom               = NULL;
static pfn_WSASend                o_WSASend                = NULL;
static pfn_WSARecv                o_WSARecv                = NULL;
static pfn_WSASendTo              o_WSASendTo              = NULL;
static pfn_WSARecvFrom            o_WSARecvFrom            = NULL;
static pfn_WSAGetOverlappedResult o_WSAGetOverlappedResult = NULL;

// ---------- 落盘 ----------
static void log_pkt(char dir, const char* data, int len, const struct sockaddr* sa)
{
    if (!g_file || !data || len <= 0) return;

    uint32_t ip = 0;
    uint16_t port = 0;
    if (sa && sa->sa_family == AF_INET) {
        const struct sockaddr_in* in4 = (const struct sockaddr_in*)sa;
        ip   = ntohl(in4->sin_addr.s_addr);
        port = ntohs(in4->sin_port);
    }

    uint32_t n  = (uint32_t)len;
    uint64_t ts = GetTickCount64();

    EnterCriticalSection(&g_cs);
    if (g_file) {
        fwrite(&dir,  1, 1, g_file);
        fwrite(&n,    4, 1, g_file);
        fwrite(&ts,   8, 1, g_file);
        fwrite(&ip,   4, 1, g_file);
        fwrite(&port, 2, 1, g_file);
        fwrite(data,  1, (size_t)len, g_file);
        fflush(g_file);
        g_count++;
        g_bytes += len;
    }
    LeaveCriticalSection(&g_cs);
}

static void log_wsabufs(char dir, LPWSABUF bufs, DWORD cnt, const struct sockaddr* sa)
{
    for (DWORD i = 0; i < cnt; ++i) {
        if (bufs[i].buf && bufs[i].len) log_pkt(dir, bufs[i].buf, (int)bufs[i].len, sa);
    }
}

// ---------- 重叠 I/O 记录表 ----------
static void ov_store(LPWSAOVERLAPPED ov, char dir, LPWSABUF bufs, DWORD cnt,
                     struct sockaddr* from, LPINT fromlen)
{
    if (!ov || !bufs || !cnt) return;
    EnterCriticalSection(&g_ovcs);
    for (int i = 0; i < MAX_OV; ++i) {
        if (g_ov[i].ov == NULL) {
            g_ov[i].ov   = ov;
            g_ov[i].dir  = dir;
            g_ov[i].cnt  = cnt > MAX_BUFS ? MAX_BUFS : cnt;
            for (DWORD j = 0; j < g_ov[i].cnt; ++j) g_ov[i].bufs[j] = bufs[j];
            g_ov[i].from    = from;
            g_ov[i].fromlen = fromlen;
            break;
        }
    }
    LeaveCriticalSection(&g_ovcs);
}

static void ov_complete(LPWSAOVERLAPPED ov, DWORD transferred)
{
    if (!ov || !transferred) return;
    EnterCriticalSection(&g_ovcs);
    for (int i = 0; i < MAX_OV; ++i) {
        if (g_ov[i].ov == ov) {
            const struct sockaddr* sa = NULL;
            if (g_ov[i].dir == 'R' && g_ov[i].from && g_ov[i].fromlen && *g_ov[i].fromlen > 0)
                sa = g_ov[i].from;

            DWORD remain = transferred;
            for (DWORD j = 0; j < g_ov[i].cnt && remain; ++j) {
                DWORD n = g_ov[i].bufs[j].len < remain ? g_ov[i].bufs[j].len : remain;
                if (g_ov[i].bufs[j].buf && n) log_pkt(g_ov[i].dir, g_ov[i].bufs[j].buf, (int)n, sa);
                remain -= n;
            }
            g_ov[i].ov = NULL;
            break;
        }
    }
    LeaveCriticalSection(&g_ovcs);
}

// ---------- detour ----------
static int WSAAPI h_send(SOCKET s, const char* buf, int len, int flags)
{
    log_pkt('S', buf, len, NULL);
    return o_send(s, buf, len, flags);
}

static int WSAAPI h_recv(SOCKET s, char* buf, int len, int flags)
{
    int r = o_recv(s, buf, len, flags);
    if (r > 0) log_pkt('R', buf, r, NULL);
    return r;
}

static int WSAAPI h_sendto(SOCKET s, const char* buf, int len, int flags, const struct sockaddr* to, int tolen)
{
    log_pkt('S', buf, len, to);
    return o_sendto(s, buf, len, flags, to, tolen);
}

static int WSAAPI h_recvfrom(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen)
{
    int r = o_recvfrom(s, buf, len, flags, from, fromlen);
    if (r > 0) log_pkt('R', buf, r, from);
    return r;
}

static int WSAAPI h_WSASend(SOCKET s, LPWSABUF bufs, DWORD cnt, LPDWORD sent, DWORD flags,
                            LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cb)
{
    if (ov) ov_store(ov, 'S', bufs, cnt, NULL, NULL);
    else    log_wsabufs('S', bufs, cnt, NULL);
    return o_WSASend(s, bufs, cnt, sent, flags, ov, cb);
}

static int WSAAPI h_WSARecv(SOCKET s, LPWSABUF bufs, DWORD cnt, LPDWORD recvd, LPDWORD flags,
                            LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cb)
{
    if (ov) ov_store(ov, 'R', bufs, cnt, NULL, NULL);
    int r = o_WSARecv(s, bufs, cnt, recvd, flags, ov, cb);
    if (r == 0 && !ov && recvd && *recvd) log_wsabufs('R', bufs, cnt, NULL);
    return r;
}

static int WSAAPI h_WSASendTo(SOCKET s, LPWSABUF bufs, DWORD cnt, LPDWORD sent, DWORD flags,
                              const struct sockaddr* to, int tolen,
                              LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cb)
{
    if (ov) ov_store(ov, 'S', bufs, cnt, NULL, NULL);
    else    log_wsabufs('S', bufs, cnt, to);
    return o_WSASendTo(s, bufs, cnt, sent, flags, to, tolen, ov, cb);
}

static int WSAAPI h_WSARecvFrom(SOCKET s, LPWSABUF bufs, DWORD cnt, LPDWORD recvd, LPDWORD flags,
                                struct sockaddr* from, LPINT fromlen,
                                LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cb)
{
    if (ov) ov_store(ov, 'R', bufs, cnt, from, fromlen);
    int r = o_WSARecvFrom(s, bufs, cnt, recvd, flags, from, fromlen, ov, cb);
    if (r == 0 && !ov && recvd && *recvd) log_wsabufs('R', bufs, cnt, from);
    return r;
}

static BOOL WSAAPI h_WSAGetOverlappedResult(SOCKET s, LPWSAOVERLAPPED ov, LPDWORD cbTransfer,
                                            BOOL fWait, LPDWORD flags)
{
    BOOL r = o_WSAGetOverlappedResult(s, ov, cbTransfer, fWait, flags);
    if (r && cbTransfer && *cbTransfer) ov_complete(ov, *cbTransfer);
    return r;
}

// ---------- 初始化 ----------
static void open_log()
{
    wchar_t exe[MAX_PATH] = {0};
    GetModuleFileNameW(NULL, exe, MAX_PATH);
    wchar_t* slash = wcsrchr(exe, L'\\');
    if (slash) *slash = 0;

    swprintf_s(g_outdir, MAX_PATH, L"%s\\pktcap", exe);
    CreateDirectoryW(g_outdir, NULL);

    wchar_t path[MAX_PATH];
    SYSTEMTIME st; GetLocalTime(&st);
    swprintf_s(path, MAX_PATH, L"%s\\pkt_%04d%02d%02d_%02d%02d%02d_pid%lu.bin",
               g_outdir, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
               GetCurrentProcessId());

    g_file = _wfopen(path, L"wb");
    if (g_file) {
        const char hdr[8] = {'P','K','T','C','A','P','0','1'};
        uint32_t ver = 2;
        fwrite(hdr, 1, 8, g_file);
        fwrite(&ver, 4, 1, g_file);
        fflush(g_file);
    }
}

static DWORD WINAPI worker(LPVOID)
{
    // 本线程由 DllMain 创建，必须等 DllMain 返回、加载器锁释放后再动手
    Sleep(1500);

    InitializeCriticalSection(&g_cs);
    InitializeCriticalSection(&g_ovcs);
    open_log();

    // 只等 ws2_32 自己出现，绝不主动 LoadLibrary
    HMODULE ws2 = NULL;
    for (int i = 0; i < 120; ++i) {
        ws2 = GetModuleHandleW(L"ws2_32.dll");
        if (ws2) break;
        Sleep(100);
    }
    if (!ws2) return 0;

    if (MH_Initialize() != MH_OK) return 0;

    struct { const char* name; LPVOID det; LPVOID* orig; } hooks[] = {
        { "send",                  (LPVOID)h_send,                  (LPVOID*)&o_send                  },
        { "recv",                  (LPVOID)h_recv,                  (LPVOID*)&o_recv                  },
        { "sendto",                (LPVOID)h_sendto,                (LPVOID*)&o_sendto                },
        { "recvfrom",              (LPVOID)h_recvfrom,              (LPVOID*)&o_recvfrom              },
        { "WSASend",               (LPVOID)h_WSASend,               (LPVOID*)&o_WSASend               },
        { "WSARecv",               (LPVOID)h_WSARecv,               (LPVOID*)&o_WSARecv               },
        { "WSASendTo",             (LPVOID)h_WSASendTo,             (LPVOID*)&o_WSASendTo             },
        { "WSARecvFrom",           (LPVOID)h_WSARecvFrom,           (LPVOID*)&o_WSARecvFrom           },
        { "WSAGetOverlappedResult",(LPVOID)h_WSAGetOverlappedResult,(LPVOID*)&o_WSAGetOverlappedResult },
    };

    for (auto& h : hooks) {
        LPVOID target = (LPVOID)GetProcAddress(ws2, h.name);
        if (target && MH_CreateHook(target, h.det, h.orig) == MH_OK) MH_EnableHook(target);
    }
    return 0;
}

extern "C" __declspec(dllexport) long  PktCap_Count() { return g_count; }
extern "C" __declspec(dllexport) long  PktCap_Bytes() { return g_bytes; }
extern "C" __declspec(dllexport) const wchar_t* PktCap_Dir() { return g_outdir; }

// ---- UE4SS C++ mod 兼容 ----
// UE4SS 的 CppMod 加载流程：LoadLibraryExW(dlls\main.dll) -> GetProcAddress("start_mod")
// -> GetProcAddress("uninstall_mod")。任一导出缺失就会 FreeLibrary，把我们的钩子一起撕掉。
extern "C" __declspec(dllexport) void* start_mod() { return NULL; }
extern "C" __declspec(dllexport) void  uninstall_mod(void*) {}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        HANDLE t = CreateThread(NULL, 0, worker, NULL, 0, NULL);
        if (t) CloseHandle(t);
    }
    return TRUE;
}
