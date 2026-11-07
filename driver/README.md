# driver/ —— 可选组件，不是主路径

## 结论先行

**不需要驱动。** 实测证明 `SendInput` 对绝大多数游戏完全干净。

## 实测数据

| 通道 | Raw Input 层 | 低级钩子层 |
|---|---|---|
| `SendInput` 键盘 | `ExtraInfo=0x00000000`，无标记 | `LLKHF_INJECTED=1` |
| `SendInput` 鼠标 | `ExtraInfo=0x00000000`，无标记 | `LLMHF_INJECTED=1` |
| `InjectSyntheticPointerInput` | 见下 | 见下 |

复现命令：
```
build/rawspy.exe all      # Raw Input 层
build/llspy.exe           # 低级钩子层
```

关键事实：**`RAWKEYBOARD` / `RAWMOUSE` 结构里根本没有 `dwExtraInfo` 字段**。
注入标记是 `KBDLLHOOKSTRUCT` / `MSLLHOOKSTRUCT` 才有的，而低级钩子要求：
- 安装者有自己的消息泵线程
- 是全局钩子（`WH_KEYBOARD_LL` / `WH_MOUSE_LL`）
- 能被 `SetWindowsHookEx` 枚举出来（可被反向发现）

目标游戏若使用 Raw Input，`SendInput` 完全干净。

## 那这个驱动还有什么用

只在两种情况下才值得启用：

1. **目标环境装了全局低级钩子**——运行时用 `hookprobe::may_see_injection()` 探测
   （时序侧信道：全局钩子串行回调，链上钩子越多 `SendInput` 越慢）
2. **需要绕过 Raw Input 之外的通道**——比如游戏校验 HID 设备枚举

两种情况都罕见。默认构建不启用驱动。

## 不花钱的路线（推荐的完整方案）

```
SendInput
  ├── 人类化时序（对数正态 + 幂律长尾）
  ├── 贝塞尔曲线轨迹（首点精确、末点收敛）
  ├── 疲劳曲线（连击越多越慢）
  └── hookprobe 探测环境
        ├── 环境干净（Raw Input）→ 直接用，零成本零风险
        └── 环境可疑（有全局钩子）→ 才考虑驱动

HID 层（无签名）
  ├── InjectSyntheticPointerInput（PT_TOUCH 可用，PT_MOUSE 保留）
  │     实测：CreateSyntheticPointerDevice(PT_MOUSE) 返回 NULL/err=87
  │           CreateSyntheticPointerDevice(PT_TOUCH) 成功
  │     限制：产生的是触摸事件，游戏要接受触摸输入才有用
  └── 自建 HID miniport（VHF/HIDCLASS）—— 需要驱动签名

桌面/会话层（无签名）
  └── UIAccess + 独立桌面 —— 需要 EV 证书
```

## 如果确实要驱动

`driver/` 下的源码是可用的（`memkit_drv.c`，900 行，已用 WDK 编译验证）。

构建：
```
cd driver && build.bat              # 产出 memkit_drv.sys
cd driver && set MEMKIT_SIGN=1 && build.bat   # 顺便签名
```

签名两条不花钱的路：
- **Microsoft attestation signing**：需要 EV 证书（$300-500/年），不算免费
- **禁用强制签名**（`bcdedit /set testsigning on`）：免费，但这个标志本身可被检测

如果两条都不走，驱动加载不了。

## 构建踩过的坑（记录备查）

| 现象 | 原因 | 处理 |
|---|---|---|
| `No Target Architecture` | `ntdef.h` 靠 `_AMD64_` 选架构 | `/D_AMD64_` |
| C4819 淹没真错误 | 中文注释 + GBK 代码页 | `/utf-8` |
| `__stdio_common_vswprintf` 找不到 | `RtlStringCchPrintfW` 拉进 CRT | 改 `RtlCopyMemory` 手工拼 |
| `ObReferenceObjectByName` 未定义 | 未公开 API，WDK 无声明 | 改 `IoGetDeviceObjectPointer` |
| bat 报"此时不应有 \Windows" | 路径含 `(x86)`，`if(...)` 块把括号当语句分隔 | 改用 `goto` |
| bat 里路径被吃字符 | `\b` `\1` `\t` 被当转义 | 路径用正斜杠 |
| `IOCTL_KEYBOARD_INSERT_KEYBOARD_INPUT_DATA` 不存在 | 坊间误传 | 是 `IOCTL_KEYBOARD_INSERT_DATA` |
| kbdclass 收到 IOCTL 后失败 | 没设 `FileObject` | `IoGetNextIrpStackLocation(irp)->FileObject = ...` |
| 链接失败 `__security_cookie` | MSVC 默认栈保护 | `/GS-` |
| Rich 头 + Debug 目录泄漏工具链 | MSVC 默认行为 | `tools/strip_pe.py`（**必须在签名前**） |
