"""把 DLL 注入到指定进程（CreateRemoteThread + LoadLibraryW）。

用法:
    python inject.py <dll路径> [进程名] [--wait 秒数]

默认进程名 KartDrift-Win64-Shipping.exe；--wait 会轮询等待进程出现。
"""
import ctypes, ctypes.wintypes as wt, sys, time, os

k32 = ctypes.WinDLL("kernel32", use_last_error=True)

PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT_RESERVE = 0x3000
PAGE_READWRITE = 0x04

k32.OpenProcess.restype = wt.HANDLE
k32.VirtualAllocEx.restype = ctypes.c_void_p
k32.VirtualAllocEx.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_size_t, wt.DWORD, wt.DWORD]
k32.WriteProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.CreateRemoteThread.restype = wt.HANDLE
k32.CreateRemoteThread.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD)]
k32.GetModuleHandleW.restype = ctypes.c_void_p
k32.GetProcAddress.restype = ctypes.c_void_p
k32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]


def find_pid(name):
    import subprocess
    try:
        out = subprocess.check_output(
            ["tasklist", "/fi", f"imagename eq {name}", "/fo", "csv", "/nh"],
            stderr=subprocess.DEVNULL).decode("gbk", errors="replace").strip()
    except Exception:
        return None
    if not out or out.startswith("信息") or "INFO" in out.upper():
        return None
    first = out.splitlines()[0]
    parts = first.split('","')
    if len(parts) < 2:
        return None
    try:
        return int(parts[1].strip('"'))
    except ValueError:
        return None


def inject(pid, dll_path):
    h = k32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h:
        print("OpenProcess 失败:", ctypes.get_last_error()); return False

    buf = (ctypes.c_wchar * (len(dll_path) + 1))(*dll_path)
    size = ctypes.sizeof(buf)
    addr = k32.VirtualAllocEx(h, None, size, MEM_COMMIT_RESERVE, PAGE_READWRITE)
    if not addr:
        print("VirtualAllocEx 失败:", ctypes.get_last_error()); return False

    written = ctypes.c_size_t(0)
    if not k32.WriteProcessMemory(h, addr, buf, size, ctypes.byref(written)):
        print("WriteProcessMemory 失败:", ctypes.get_last_error()); return False

    k32.GetModuleHandleW.restype = ctypes.c_void_p
    hk = k32.GetModuleHandleW("kernel32.dll")
    load_lib = k32.GetProcAddress(hk, b"LoadLibraryW")
    if not load_lib:
        print("找不到 LoadLibraryW"); return False

    tid = wt.DWORD(0)
    th = k32.CreateRemoteThread(h, None, 0, load_lib, ctypes.c_void_p(addr), 0, ctypes.byref(tid))
    if not th:
        print("CreateRemoteThread 失败:", ctypes.get_last_error()); return False

    k32.WaitForSingleObject(th, 8000)
    code = wt.DWORD(0)
    k32.GetExitCodeThread(th, ctypes.byref(code))
    k32.CloseHandle(th)
    k32.CloseHandle(h)

    if code.value == 0:
        print(f"注入失败（LoadLibrary 返回 0），PID={pid}")
        return False
    print(f"注入成功 PID={pid} 模块句柄=0x{code.value:X}")
    return True


def main():
    if len(sys.argv) < 2:
        print(__doc__); return
    dll = os.path.abspath(sys.argv[1])
    name = sys.argv[2] if len(sys.argv) > 2 and not sys.argv[2].startswith("--") else "KartDrift-Win64-Shipping.exe"
    wait_s = 0
    if "--wait" in sys.argv:
        i = sys.argv.index("--wait")
        wait_s = int(sys.argv[i + 1]) if i + 1 < len(sys.argv) else 60

    if not os.path.isfile(dll):
        print("DLL 不存在:", dll); return

    deadline = time.time() + wait_s
    pid = None
    while True:
        pid = find_pid(name)
        if pid or time.time() >= deadline:
            break
        time.sleep(0.2)   # 尽量赶在登录握手前注入

    if not pid:
        print(f"没找到进程: {name}")
        return
    inject(pid, dll)


if __name__ == "__main__":
    main()
