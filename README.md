# UE4SS-KartRiderDrift

针对 **Themida 加壳的《跑跑卡丁车：漂移》客户端**（KartRider Drift，UE 4.27 / Win64）的 UE4SS 4.0.0 修复构建。

修复了 UE4SS 在加壳 PE 上随机崩溃（约 50%）的问题，并附带一个 socket 层抓包工具，用于协议分析。

---

## 一、问题现象

UE4SS 4.0.0 注入后，进程在初始化阶段随机终止（约 50% 概率），日志固定停在：

```
[PS] Reading image
```

有时能撑过去，有时直接死。Windows 事件日志里**没有任何 Application Error / WER 记录**，说明不是普通的访问违例。

UE4SS 控制台里能看到真正的原因：

```
thread '<unnamed>' panicked at deps\first\patternsleuth\src\process\internal.rs:58:44:
range start index 1200470886 out of range for slice of length 142950400
note: panic in a function that cannot unwind
```

- `142950400` = `0x8854000` = 客户端的 `SizeOfImage`
- `1200470886` = `0x478F2B26` = 越界的切片起点

---

## 二、根因

`patternsleuth`（UE4SS 的 Rust 签名扫描库）在 Windows 下这样取节数据：

```rust
// deps/first/patternsleuth/patternsleuth/src/process/internal.rs
let memory = unsafe {
    std::slice::from_raw_parts(
        mod_info.lpBaseOfDll as *mut u8,
        mod_info.SizeOfImage as usize,
    )
};

let object = object::File::parse(memory)?;
let image_base_address = object.relative_address_base();

for section in object.sections() {
    let addr = (section.address() - image_base_address) as usize;
    let size = section.size() as usize;
    sections.push((section, &memory[addr..addr + size]));   // ← 无边界检查
}
```

三个问题：

1. `section.address() - image_base_address` 是**无符号减法**，节表异常时下溢成天文数字
2. `&memory[addr..addr + size]` **没有任何 `addr + size <= memory.len()` 校验**
3. `memory` 由 `from_raw_parts` 直接构造，内容完全不校验

Themida 会在运行时改写内存中的 PE 头（反 dump 常规操作）。扫描时若节表已被改写，`addr` 就越界。

**为什么是 50%**：取决于 UE4SS 开始扫描的那一刻，内存里的 PE 头是否已被改写。
**为什么延迟无效**：延迟只会让扫描必然落在改写之后，反而变成 100% 失败。

> Rust 的 panic 在跨越 `extern "C"` 边界时无法 unwind，直接走 `abort()`，所以是**整个进程终止**，而不是仅该线程退出。

---

## 三、修复

在越界时跳过该节，而不是 panic：

```rust
for section in object.sections() {
    let addr = (section.address() - image_base_address) as usize;
    let size = section.size() as usize;
    if addr
        .checked_add(size)
        .map_or(true, |end| end > memory.len())
    {
        continue;
    }
    sections.push((section, &memory[addr..addr + size]));
}
```

补丁文件见 [`patches/patternsleuth-bounds-check.patch`](patches/patternsleuth-bounds-check.patch)。

应用方式（在 `RE-UE4SS` 仓库根目录）：

```bash
git submodule update --init --recursive
git -C deps/first/patternsleuth apply ../../patches/patternsleuth-bounds-check.patch
```

---

## 四、构建

### 环境

| 组件 | 版本 |
|---|---|
| MSVC | 14.51（VS 2026，工具集 v145） |
| Windows SDK | 10.0.26100.0 |
| CMake | 4.3.1 |
| Ninja | 1.13.2 |
| Rust | 1.88.0 |

### 命令

```powershell
$msvc = "E:\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231"
$sdk  = "E:\Windows Kits\10"; $ver = "10.0.26100.0"
$ninja = "E:\Microsoft Visual Studio\18\Enterprise\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja"
$cmake = "E:\Microsoft Visual Studio\18\Enterprise\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"

$env:INCLUDE = "$msvc\include;$sdk\Include\$ver\ucrt;$sdk\Include\$ver\um;$sdk\Include\$ver\shared;$sdk\Include\$ver\winrt"
$env:LIB     = "$msvc\lib\x64;$sdk\Lib\$ver\ucrt\x64;$sdk\Lib\$ver\um\x64"
$env:PATH    = "$msvc\bin\Hostx64\x64;$sdk\bin\$ver\x64;$ninja;C:\Users\<you>\.cargo\bin;$env:PATH"

cmake -B build_ninja -G Ninja -DCMAKE_BUILD_TYPE=Game__Shipping__Win64 `
      -DCMAKE_C_COMPILER=cl -DCMAKE_CXX_COMPILER=cl
cmake --build build_ninja
```

产物：`build_ninja/Game__Shipping__Win64/bin/UE4SS.dll`（约 20.8 MB）

> 用 `Visual Studio 18 2026` 生成器时 CMake 找不到编译器（VS 实例未注册给 CMake），所以走 Ninja + 手动设置 MSVC 环境变量。

---

## 五、必须的第二个补丁：DllMain 分支（1 字节）

UE4SS 原版在 `dll_process_attached` 里判断当前线程是否主线程：

```cpp
if (GetCurrentThreadId() == get_main_thread_id()) {
    QueueUserAPC(process_initialized, GetCurrentThread(), moduleHandle);   // 等主线程 alertable
} else {
    process_initialized(moduleHandle);                                     // 直接执行
}
```

通过代理 DLL 加载时走的是 APC 分支，但**这个客户端的主线程从不进入 alertable 等待**，APC 永远不触发 → UE4SS 初始化永远不执行。

解决办法：把 `jne`（跳过 APC 分支）改成 `jmp`，强制走直接调用。

### 定位方法

在 `UE4SS.dll` 中搜索字节模式：

```
3B C7 75 ?? C6 05 ?? ?? ?? ?? 01
```

即 `cmp eax, edi` / `jne +0x??` / `mov byte ptr [rip+xxxxxxxx], 1`（置 `s_wait_for_ue4ss = 1`）。

把 `75`（`jne`）改成 `EB`（`jmp`）即可。

### 本次构建的偏移

| 项 | 值 |
|---|---|
| 文件偏移 | `0x3F0FE0` |
| 原字节 | `75` |
| 改为 | `EB` |

> 偏移**随构建变化**，重新编译后必须重新定位，不要直接套用。

---

## 六、验证结果

修复后连续启动 3 次：

| 轮次 | 进程 | 日志行数 | 扫描 | 结果 |
|---|---|---|---|---|
| 1 | ALIVE | 898 | 成功 | 无 panic |
| 2 | ALIVE | 904 | 成功 | 无 panic |
| 3 | ALIVE | 928 | 成功 | 无 panic |

日志均推进到 `FCallbackGarbageCollector`（主循环阶段）。

修复前：约 50% 概率在 `[PS] Reading image` 处进程终止。

---

## 七、附带工具：socket 层抓包

`pktcap/` 是一个独立 DLL，hook `ws2_32` 的收发函数，把原始字节落盘。用于协议分析 / 服务器模拟器研究。

### 支持

- `send` / `recv` / `sendto` / `recvfrom`
- `WSASend` / `WSARecv` / `WSASendTo` / `WSARecvFrom`
- **重叠 I/O**：通过 hook `WSAGetOverlappedResult`，用 overlapped 指针回查缓冲区

### 落盘格式

```
[0]       char     'S'=发送 'R'=接收
[1..4]    uint32   载荷长度
[5..12]   uint64   GetTickCount64 时间戳(ms)
[13..16]  uint32   对端 IPv4
[17..18]  uint16   对端端口
[19..]    bytes    载荷
```

文件头：`PKTCAP01` + `uint32` 版本号（当前 2）

### 使用

两种加载方式：

1. **作为 UE4SS C++ mod**：放到 `ue4ss/Mods/PktCap/dlls/main.dll`，并在 `mods.txt` 加 `PktCap : 1`
   - 该 DLL 导出了 `start_mod` / `uninstall_mod`（返回 `NULL`），满足 UE4SS 的 mod 加载要求
2. **独立注入**：`python inject.py pktcap.dll`

解析：`python pktdump.py <文件> [--hex] [--max N]`

---

## 八、注意事项

- 本仓库**不包含**任何游戏文件、客户端二进制或 UE4SS 的完整源码，只有补丁和自研工具。
- 补丁针对的是 UE4SS 上游的一个真实 bug（对不可信输入缺少边界检查），理论上对所有加壳 PE 都有意义。
- 抓包工具仅用于分析自己有权访问的客户端与服务端通信。

---

## 九、文件清单

```
patches/patternsleuth-bounds-check.patch   patternsleuth 越界修复
scripts/switch_ue4ss.bat                   UE4SS 版本切换（2.5.2 / 4.0.0）
pktcap/src/pktcap.cpp                      抓包 DLL 源码
pktcap/inject.py                           DLL 注入器
pktcap/pktdump.py                          抓包解析器
```
