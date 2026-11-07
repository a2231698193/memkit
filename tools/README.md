# tools/ —— 审计与实测工具

## 回归审计

```bash
py -3 tools/audit.py build/memkit.exe
py -3 tools/audit.py driver/memkit_drv.sys
```

五项检查，任一失败返回非零（可作 CI 网关）：

1. **敏感导入**：`OpenProcess` / `ReadProcessMemory` / `CreateRemoteThread` /
   `SetWindowsHookExW` / `GetThreadContext` 等
2. **依赖 DLL 白名单**：只允许 `kernel32/user32/bcrypt/msvcrt/ntdll` 等
3. **明文串**：`Warden` / `Nt*` / `LLMHF` / `frida`（可自行扩展白名单）
4. **PE 卫生**：无 Debug 目录、无 `.comment`、无 Rich 头
5. **段名**：无 MinGW 可辨识段

驱动（`.sys`）走另一套规则：只允许 `ntoskrnl.exe` / `hal.dll`，
且禁止任何 CRT 符号（`__cxa_` / `malloc` / `printf` / `__security_init_cookie`）。

## PE 清理

```bash
py -3 tools/strip_pe.py <file.exe|file.sys>
```

清 Rich 头（MSVC 编译器版本指纹）+ Debug 目录（PDB 路径 + coffgrp 参数摘要）。

**顺序很重要**：strip 必须在 sign 之前。签名会给整个文件做哈希，
之后再改字节会让签名失效。

## 实测工具（决定架构的那两个）

### `rawspy.cpp` —— Raw Input 层可见性

```bash
rawspy.exe sendinput    # 测 SendInput
rawspy.exe postmsg      # 测 PostMessage
rawspy.exe synthetic    # 测 InjectSyntheticPointerInput
rawspy.exe all
```

输出形如：
```
[KBD] wParam=RIM_INPUTSINK VKey=0x41 Scan=0x1E Flags=0x0000 Msg=DOWN
      ExtraInfo=0x00000000 LLInjected=0 InjectedBit=0 AsyncState=0x8001
[MOU] wParam=RIM_INPUTSINK usFlags=0x0000 Buttons=0x0000 LastX=10 LastY=5
      ExtraInfo=0x00000000 LLInjected=0 InjectedBit=0
```

关键：`ExtraInfo=0x00000000`，`LLInjected=0`。
**Raw Input 层看不到 SendInput 的注入标记。**

### `llspy.cpp` —— 低级钩子层可见性

```bash
llspy.exe
```

输出：
```
[LL-KBD] vk=0x41 scan=0x1E flags=0x00000010 LLKHF_INJECTED=1 ExtraInfo=0x00000000
[LL-MOU] pt=(578,1290) flags=0x00000001 LLMHF_INJECTED=1 ExtraInfo=0x00000000
```

关键：`LLKHF_INJECTED=1`。
**低级钩子层能看到标记。**

### `hookdetect.cpp` —— 对方是否装了钩子

```bash
hookdetect.exe
```

用时序侧信道：全局钩子是串行回调的，`SendInput` 必须等链上每个钩子
返回才返回。所以链上钩子越多，`SendInput` 单次耗时越高。

本机实测：
```
[baseline]  SendInput avg = 158 us
[with-hook] SendInput avg = 177 us  (delta = +19 us)
```

每个钩子约 **20us**。基线超过 320us（2 倍）就认为链上有别人。

## 结论汇总

| 问题 | 答案 |
|---|---|
| SendInput 会被 Raw Input 看到标记吗 | **不会**。结构里没这个字段 |
| SendInput 会被低级钩子看到标记吗 | **会**。`LLKHF_INJECTED=1` |
| 目标用哪个通道 | 需实测（rawspy） |
| 所以需要驱动吗 | **不需要** |
| InjectSyntheticPointerInput 能替代 SendInput 吗 | **不能**。只支持 TOUCH/PEN，不支持 MOUSE |
