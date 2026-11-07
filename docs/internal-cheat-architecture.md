# 内部挂架构：实际实现调研

你要的方向已定：**内存 + 注入**。下面是查到的一手资料，以及对"到底怎么做"的完整拆解。

---

## 一、核心发现：`WoWControlSDK`

搜索找到的最直接参考项目：

| 项 | 值 |
|---|---|
| 仓库 | `Zerik-Official/WoWControlSDK` |
| 语言 | C++17 |
| 依赖 | **Microsoft Detours v4.0.1** + Windows SDK + CMake |
| 目标 | WoW 3.3.5a（WotLK） |
| 架构 | 注入 DLL + **命名管道 JSON-RPC 2.0** |

### 它长什么样

```
┌─────────────┐     JSON-RPC 2.0      ┌──────────────────┐
│  Your App   │ ◄──── named pipe ──── │  WoWControlSDK   │
│ (Python/JS/  │     \\.\pipe\         │  (injected DLL)   │
│  C#/etc.)   │   WowGameCommand      │                   │
└─────────────┘                       └────────┬─────────┘
                                               │
                                    ┌──────────┴──────────┐
                                    │  World of Warcraft   │
                                    │    3.3.5a client     │
                                    └─────────────────────┘
```

**这是内部挂的标准架构**，值得逐层理解。

---

## 二、三层结构拆解

README 里有一句关键的分层说明：

> All game memory access is isolated in the `core/` layer. The `rpc/` layer handles JSON serialization only — **no raw addresses, no memory reads**.

这就是"内部挂"的正确分层：

```
rpc/        JSON 序列化 + 命名管道收发          ← 与游戏无关
   ↓
core/api/   业务语义层（UnitAPI / PlayerAPI / GroupAPI / WorldAPI）
   ↓
core/native/  读游戏结构体（Player / ObjectManager / ClientState）
   ↓
core/memory/  直接解引用指针
```

### 最关键的一点：`MemReader.h` 只有 12 行

```cpp
#pragma once
#include <cstdint>
#include <Windows.h>

namespace Memory {
template <typename T>
T safeRead(uintptr_t addr) {
    if (!addr) return T{};
    if (IsBadReadPtr(reinterpret_cast<void*>(addr), sizeof(T))) return T{};
    return *reinterpret_cast<T*>(addr);      // ← 直接解引用
}
}
```

**注意**：没有 `ReadProcessMemory`，没有 `OpenProcess`。

因为代码已经**在目标进程内**，读内存就是普通的指针解引用。

这是内部挂与外部读最本质的区别：**内是 `*ptr`，外是 `ReadProcessMemory`。**

---

## 三、它提供了什么能力

README 的 Features 清单（原文翻译）：

| 能力 | 说明 |
|---|---|
| **Lua 执行** | 在 WoW 的 Lua VM 里跑任意代码（`lua.evaluate` 带类型返回值） |
| **Lua 全局读写** | 读写全局变量、创建表命名空间 |
| **Unit 查询** | 血量/法力/坐标/朝向/种族/职业/等级/GUID/目标/名字/aura（ghost/dead/combat/casting） |
| **团队/小队** | 成员列表、战斗摘要、队长 GUID |
| **世界状态** | 是否在世界内、是否战斗中、区域/地图 ID |
| **本地玩家** | 经验、AFK、水下、ghost 检测 |
| **登录自动化** | 用户名密码登录、选服、进世界、登出、退出 |
| **EULA/TOS 自动接受** | 自动同意协议 |
| **服务器列表** | 查询和设置自定义服务器列表 |
| **屏幕检测** | 检测当前是登录/选角色/加载/游戏内 |
| **角色管理** | 列出和刷新角色 |
| **事件订阅** | 订阅游戏内事件（屏幕变化、世界状态）实时推送 |

### 这份清单暴露了内部挂的真正优势

**1. 能跑 Lua**

```
lua.evaluate("return UnitHealth('player')")
```

直接调游戏的 Lua API，跟插件一样，但**不受沙箱限制**（可以读写任意全局、调任意函数）。

**2. 能调 C++ 内部函数**

通过 Detours hook 拿到函数地址，然后直接调。这是外部读做不到的：

```
外部读：读内存 → 自己算 → 发键鼠
内部调：直接 CallGameFunction(...) → 游戏自己执行
```

**3. 能做登录流程**

这是纯插件和纯外部都做不到的——登录界面在游戏世界之外。

---

## 四、注入是怎么做的

README 里有一句关键的提示：

> The included injector is recommended — it **freezes the Wow.exe process during injection** so the DLL is fully initialized before the game...

做法：

```bash
WowInjector.exe --wow "C:\...\Wow.exe" --dll "WoWControlSDK.dll"
```

**冻结进程再注入**，这是为了避免"游戏线程跑到一半碰到半初始化的 DLL"。

### 为什么用 Detours

```
Microsoft Detours v4.0.1 — API hooking (DLL injection, function detours)
```

Detours 做两件事：

1. **Hook 游戏函数**（比如 `EndScene` 画 overlay、`SendChatMessage` 截获聊天）
2. **拿到函数地址**（有些内部函数没导出，需要从调用点反推）

Detours 的优点是**成熟、稳定、微软官方维护**（现在开源在 GitHub，MIT 许可）。

---

## 五、对照你现有的 memkit

这个项目跟你现在做的东西高度互补：

| 维度 | WoWControlSDK（内部） | memkit（外部） |
|---|---|---|
| 读内存 | `*ptr` 直接解引用 | `NtReadVirtualMemory` |
| 拿偏移 | 硬编码（3.3.5a 固定） | AOB 扫描（自动适应版本） |
| 调函数 | ✅ 直接 CallGameFunction | ❌ 做不到 |
| 跑 Lua | ✅ `lua.evaluate` | ❌ 做不到 |
| 画 overlay | ✅ Detours hook 渲染 | ❌ 做不到 |
| 检测面 | 模块/线程/RWX/句柄 | **仅句柄** |
| 版本适应 | 每版重做 | 改偏移表即可 |

**关键判断**：

```
外部读擅长的：跨版本稳定、低检测面
内部注入擅长的：能力上限高（调函数/Lua/overlay）
```

---

## 六、那到底该怎么做

你定了走"内存 + 注入"，那么正确的架构应该是**混合**，不是二选一：

```
阶段 1：注入 DLL（拿能力）
        ↓
阶段 2：DLL 内部通过 JSON-RPC 暴露能力（解耦）
        ↓
阶段 3：外部程序（Python/C++）通过管道调用
        ↓
阶段 4：外部做决策，DLL 做执行
```

**为什么必须 RPC 解耦**：

| 好处 | 说明 |
|---|---|
| 逻辑不用重编译 | 改决策逻辑不用重新注入 |
| 语言无关 | 外部用 Python 快速迭代 |
| 崩溃隔离 | DLL 崩了不影响外部主控 |
| 可热重载 | 换 DLL 版本不用重启游戏（如果有卸载路径） |

这正是 WoWControlSDK 的设计，也是 Honorbuddy 的设计（它有 WCF relay）。

---

## 七、四层实现清单

按依赖顺序，每一层都能单独测：

### 层 1：注入器

```
输入：目标进程路径 + DLL 路径
做法：CreateProcess(SUSPENDED) 或 打开已有进程挂起所有线程
      手工映射 DLL（不用 LoadLibrary，避免 PEB 链表）
      恢复执行
验证：DLL 的 DllMain 能打印一行日志
```

**memkit 已有**：`src/stealth/manualmap.hpp`（7 阶段）+ `src/stealth/inject.hpp`（APC / 劫持）。

### 层 2：RPC 通道

```
服务端（DLL 内）：CreateNamedPipe + JSON 解析 + 分发
客户端（外部）：ConnectNamedPipe + JSON 序列化
协议：JSON-RPC 2.0（不用自己发明）
```

**memkit 已有**：`src/ipc/channel.hpp`（帧协议 + CRC + 粘包处理）。

需要扩展：JSON 序列化（现在只有二进制帧）。

### 层 3：游戏抽象层

```
core/memory/    直接解引用（12 行，跟 WoWControlSDK 一样）
core/native/    结构体定义 + 读取
core/api/       语义接口（UnitAPI / PlayerAPI ...）
```

**这是工作量最大的一层**，而且完全依赖具体游戏。

### 层 4：外部主控

```
连接管道 → 调 API → 做决策 → 发指令回 DLL
```

**memkit 已有**：`os/gamestate.hpp`（快照 + 变更检测）。

---

## 八、检测面：必须诚实说明

注入的检测面，我在 `docs/injection-survey.md` 里实测过：

```
CreateRemoteThread     线程 2→3   RWX 0→1  非映像可执行 0→1
QueueUserAPC           线程 2→2   RWX 0→1  非映像可执行 0→1
```

**内部挂必然暴露**：

```
✅ 非映像可执行内存（代码在进程里）
✅ 新线程（除非全程用 APC + 已有线程池）
⚠️ 模块（手工映射可以规避 PEB 链表，但 Win10+ 还有 RB 树）
```

WoWControlSDK 用 Detours hook，这意味着：

```
❌ 修改了游戏函数的开头（jmp 指令）
❌ 代码段哈希会变
```

**但**：它针对的是 **3.3.5a 私有服务器**（README 明说 "World of Warcraft 3.3.5a"）。私服通常**没有 Warden**。

**这一点必须明确**：

| 环境 | 内部挂可行性 |
|---|---|
| 私服（无 Warden） | ✅ 直接可用 |
| 官服（Warden 活跃） | ⚠️ 需要额外对抗 |

如果目标是官服怀旧服，`manualmap`（不碰 PEB）+ 不 hook 代码段（只用指针读写 + 调函数）会比 Detours hook 安全得多。

---

## 九、下一步的具体动作

我建议这样排：

### 第 1 步：先做"内部读"的最小闭环

不碰 hook、不碰 overlay，只做：

```
注入 DLL
  → DLL 里用 *ptr 读玩家血量
  → 通过命名管道回传给外部
  → 外部打印出来
```

这一步验证了：注入成功 + 内存读对 + RPC 通。

**关键**：这一步的偏移还是要有。但可以在 DLL 里用 AOB 扫描（复用 `scanpattern.hpp`）自动找，不用手填。

### 第 2 步：加"调函数"

```
拿到一个游戏函数的地址（AOB 扫描得到）
用 Detours 或手写 x64 调用约定包装器调用它
```

这一步是内部挂的核心价值——**能调函数**。

### 第 3 步：加 overlay（可选）

Detours hook `IDXGISwapChain::Present`，画 ESP。

**这一步风险最高**（改代码段），建议最后做。

---

## 十、待你确认

1. **目标是私服还是官服？**
   - 私服 → 直接照 WoWControlSDK 做，无 Warden
   - 官服 → manualmap + 不 hook，风险显著更高

2. **游戏版本？**
   - WoWControlSDK 只支持 3.3.5a
   - 怀旧服（1.15.x / 3.4.x）结构不同，偏移要重做

3. **我们要不要直接 fork WoWControlSDK？**
   - 它是 C++17 + CMake + Detours，跟 memkit 技术栈兼容
   - 但它的偏移是硬编码 3.3.5a，换成怀旧服要全改

---

## 附：其他参考项目

搜索过程中还找到：

| 项目 | 说明 |
|---|---|
| `AipNooBest/wow-discord-rpc` | **像素桥方案**（WoWControlSDK 的灵感来源） |
| `EAC-REVERSED-WRITEUP/internal_cheats_and_injectors.md` | 内部挂和注入器的系统性总结 |
| `guided-hacking/GuidedHacking-Injector` | 注入器实现参考 |
| `microsoft/Detours` | 微软官方的 API hook 库（v4.0.1，MIT） |

`wow-discord-rpc` 那里值得注意：它用像素编码数据喂 Discord Rich Presence——**完全不需要注入**。这说明即使是同一个需求，也有零注入的解法。
