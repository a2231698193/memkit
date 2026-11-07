# 注入技术全景：原理、实现、可检测性

本文基于对公开实现的实际阅读，不是转述。主要参考：

| 项目 | 星 | 内容 |
|---|---|---|
| [`stephenfewer/ReflectiveDLLInjection`](https://github.com/stephenfewer/ReflectiveDLLInjection) | 3386 | 反射式注入的经典实现 |
| [`rootm0s/Injectors`](https://github.com/rootm0s/Injectors) | 714 | 各种注入技术的合集（含源码） |
| [`Dec0ne/DllNotificationInjection`](https://github.com/Dec0ne/DllNotificationInjection) | 469 | 无线程注入（2023 新技术） |
| [`Hagrid29/PELoader`](https://github.com/Hagrid29/PELoader) | 466 | PE 加载器 + 多种 shellcode 注入 |
| [`shaheeryasirofficial/project-scorpio`](https://github.com/shaheeryasirofficial/project-scorpio) | 41 | PPID 伪造 + 手工映射 + 模块踩踏 |

---

## 一、注入的本质

一句话：**让目标进程执行你的代码。**

不管用什么手段，最终都是这三步：

```
1. 把代码/数据放进目标进程的地址空间
2. 让目标进程的某个线程跳转到那段代码
3. 代码执行完干净退出（或不退出）
```

所有技术的差异，都在这三步的**实现方式**上。

---

## 二、技术分类

### 按"代码怎么进去"分

| 方式 | 说明 | 需要写目标内存 |
|---|---|---|
| **LoadLibrary** | 目标从磁盘加载你的 DLL | 只需要写路径字符串 |
| **手工映射** | 自己模拟 PE 加载器 | 需要写整个映像 |
| **反射式** | 目标自己跑一段自带的加载器 | 需要写加载器 + 映像 |
| **模块踩踏** | 覆盖已加载模块的代码 | 需要写目标代码段 |
| **进程镂空** | 替换整个进程映像 | 需要挂起并重写 |

### 按"怎么触发执行"分

| 方式 | 留下什么 | 是否需要新线程 |
|---|---|---|
| `CreateRemoteThread` | **新线程** | ✅ |
| `NtCreateThreadEx` | **新线程**（更底层，可控参数） | ✅ |
| `RtlCreateUserThread` | **新线程**（未文档化） | ✅ |
| `QueueUserAPC` | 不用新线程 | ❌ |
| `SetWindowsHookEx` | 系统会调度你的 DLL | ❌ |
| **线程劫持** | 不用新线程（改现有线程 Rip） | ❌ |
| **DLL 通知回调** | 不用新线程 | ❌ |
| **AtomBombing** | 通过 Atom 表传递 | ❌ |

---

## 三、逐个技术详解

### 1. CreateRemoteThread（最基础）

```cpp
// 步骤
1. OpenProcess(PROCESS_ALL_ACCESS)
2. VirtualAllocEx 分配内存
3. WriteProcessMemory 写入 DLL 路径
4. GetProcAddress(kernel32, "LoadLibraryA")
5. CreateRemoteThread(target, LoadLibraryA, dllPath)
```

**留下什么**：

```
✅ 新线程（线程枚举可见）
✅ 线程起始地址 = kernel32!LoadLibraryA（合法模块内，但调用者是外部的）
✅ DLL 会进入 PEB 模块链表（EnumProcessModules 可见）
✅ 目标进程内会打开 DLL 文件句柄
```

**可检测性：极高。** 这是最老的技术，几乎所有反作弊的第一条规则就是它。

---

### 2. NtCreateThreadEx / RtlCreateUserThread

`CreateRemoteThread` 的底层实现。区别在于能设置更多参数：

```cpp
NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess,
                 startRoutine, parameter,
                 flags,      // 可以设 THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER
                 0, 0, 0, NULL);
```

`RtlCreateUserThread` 是 ntdll 的未文档化函数，语义类似。

**留下什么**：跟 CreateRemoteThread 一样有新线程。只是调用路径不同。

**可检测性：高。** 反作弊可以 hook `NtCreateThreadEx`，或者枚举线程后检查起始地址。

---

### 3. QueueUserAPC / NtQueueApcThread

不创建线程，而是把 APC 挂到**已存在的线程**上，等它进入 alertable wait 时执行。

```cpp
1. 打开目标线程（THREAD_SET_CONTEXT）
2. 找到处于 alertable wait 的线程
3. QueueUserAPC(apcRoutine, hThread, param)

条件：目标线程必须调用 SleepEx/WaitForSingleObjectEx/MsgWaitForMultipleObjectsEx
      且允许 alertable
```

**留下什么**：

```
⚠️ 不创建新线程（好）
⚠️ 但 APC 队列本身可被 NtQueryInformationThread 观察到
⚠️ 执行时机不确定（要等目标进入 alertable wait）
```

**可检测性：中。** 需要目标配合（处于 alertable wait），且 APC 队列有痕迹。

**为什么 memkit 默认选这个**：WoW 主循环线程长期在消息泵里 `MsgWaitForMultipleObjectsEx`，天然是 alertable 的。

---

### 4. 线程劫持（Suspend / SetContext / Resume）

```cpp
1. SuspendThread(targetThread)
2. GetThreadContext 拿到当前 Rip
3. 把 Rip 改成你的 shellcode 地址
4. SetThreadContext
5. ResumeThread

shellcode 执行完要跳回原 Rip，假装什么都没发生
```

**留下什么**：

```
✅ 不创建新线程
⚠️ SuspendThread/SetThreadContext 是强信号（有 ETW 事件）
⚠️ 需要暂停线程，目标会短暂卡顿（可被计时发现）
✅ 复用原栈，不产生新栈帧
```

**可检测性：中低。** 这是比 CreateRemoteThread 好得多的方案。主要风险是 `SetThreadContext` 的 ETW 事件和线程暂停的时序异常。

---

### 5. SetWindowsHookEx

```cpp
SetWindowsHookEx(WH_GETMESSAGE, hookProc, hDll, targetThreadId)
```

系统在目标线程的消息循环里调用你的 DLL。

**留下什么**：

```
✅ 不用 explicit 的创建线程
❌ DLL 必须真实存在于磁盘（系统要 LoadLibrary）
❌ 会进入目标进程的模块列表
❌ 全局钩子表本身可枚举
```

**可检测性：高。** 而且只对 GUI 程序有效。

---

### 6. 反射式注入（Reflective DLL Injection）

**核心思路**：DLL 自己带一个"加载器"，不需要系统的 `LoadLibrary`。

`ReflectiveLoader.c` 的做法（读了源码）：

```c
DLLEXPORT ULONG_PTR WINAPI ReflectiveLoader(VOID) {
    // 1. 用自己的返回地址找到自己在内存的位置
    uiLibraryAddress = caller();       // _ReturnAddress()
    // 2. 向上搜索 MZ/PE 头，定位映像基址
    while (TRUE) {
        if (*(USHORT*)uiLibraryAddress == 0x5A4D &&   // "MZ"
            *(ULONG*)(uiLibraryAddress + ...) == 0x00004550) break;  // "PE\0\0"
        uiLibraryAddress--;
    }
    // 3. 解析自己的导入表，手动 LoadLibrary + GetProcAddress 填 IAT
    // 4. 分配新内存，按节表拷贝
    // 5. 处理重定位
    // 6. 调 DllMain(DLL_PROCESS_ATTACH)
}
```

关键点：**这段代码是位置无关的（PIC）**，所以能在任意地址跑。

**留下什么**：

```
✅ 不进入 PEB 模块链表（没走 LdrLoadDll）
✅ 不需要 DLL 在磁盘上
❌ 反射加载器本身是特征（大段 PIC 代码）
❌ 需要一段可执行的映射内存
❌ 需要新线程来跑 ReflectiveLoader
```

**可检测性：中。** 加载器代码本身极具特征，而且通常配合 CreateRemoteThread 使用。

**memkit 的 manualmap 比这个好**：加载器留在外部进程，目标进程只接收已重定位好的映像 + 一个极小的 stub。

---

### 7. 手工映射（Manual Mapping）

`memkit/src/stealth/manualmap.hpp` 实现的就是这个。读源码理解的过程：

```
阶段 1  读磁盘 PE，解析头和节表           —— 外部
阶段 2  NtAllocateVirtualMemory 分配 RW   —— 外部
阶段 3  按节表在本地拼出完整映像          —— 外部
阶段 4  处理基址重定位（DIR64）           —— 外部
阶段 5  解析导入表、填 IAT                —— 外部（要读目标模块的导出表）
阶段 6  写入目标内存（分块）              —— 外部
阶段 7  按节改权限（.text → RX）          —— 外部
阶段 8  TLS 回调 + DllMain                —— 目标侧
```

**与反射式的本质区别**：

| | 反射式 | 手工映射 |
|---|---|---|
| 加载器在哪 | **目标进程内**（有特征） | **外部进程**（无痕迹） |
| 目标接收什么 | 原始 DLL + 一段加载器代码 | 已重定位好的完整映像 |
| 需要的目标侧代码 | 整个 ReflectiveLoader | 极小的 stub（TLS+DllMain） |

**留下什么**：

```
✅ 不进入 PEB 链表
❌ 一块非映像的可执行内存（MEM_PRIVATE + EXECUTE）
❌ 需要新线程（或 APC/劫持）来跑 DllMain
❌ 导入表的 IAT 指向目标已有模块（这个反而正常）
```

**可检测性：中低。** 主要破绽是"非映像可执行内存"和"新线程"。

---

### 8. 模块踩踏（Module Stomping）

**思路**：覆盖一个**已加载的合法模块**的代码段，把你的 shellcode 写进去。

```
1. 找一个不太用的已加载 DLL（比如某些不调用的系统库）
2. 把它的 .text 段改成 PAGE_READWRITE
3. 写入你的 shellcode
4. 改成 PAGE_EXECUTE_READ
5. 执行
```

**留下什么**：

```
✅ 内存是 MEM_IMAGE（看起来像正常模块）
✅ 没有 RWX 页
✅ 没有非映像可执行页
❌ 模块的代码段哈希变了（如果反作弊校验）
❌ .text 的页属性被改过（虽然改回来了）
```

**可检测性：中。** 规避了"非映像可执行页"的检测，但代码段完整性校验能抓到。

**注意**：这解释了为什么很多反作弊要校验所有已加载模块的 `.text` 哈希。

---

### 9. 进程镂空（Process Hollowing）

```
1. CreateProcess(SUSPENDED) 创建合法进程
2. NtUnmapViewOfSection 卸载它的映像
3. 分配新内存，写入你的映像
4. 改入口点
5. ResumeThread
```

**留下什么**：

```
✅ 进程名合法
✅ 父进程正常
❌ 内存里的映像跟磁盘上的文件对不上
❌ 入口点指向非映像区域
```

**可检测性：中。** 对比磁盘文件 vs 内存映像就能发现。

---

### 10. DLL 通知回调注入（2023 新技术）

`Dec0ne/DllNotificationInjection` 的思路（读 README）：

```
1. 在目标进程里创建自己的 LDR_DLL_NOTIFICATION_ENTRY
2. 手工把它插进 LdrpDllNotificationList
   —— patch 链表头的 Flink 和原第一个条目的 Blink
3. 这个条目指向一段 trampoline shellcode
4. 等目标进程加载/卸载任何 DLL 时，触发你的回调
5. trampoline 恢复链表修改，然后用 TpWorkCallback 起线程执行真正代码
```

**留下什么**：

```
✅ 不创建线程（用 TpWorkCallback 线程池）
✅ 不改任何模块的代码
✅ 链表修改会恢复
❌ 需要 patch LdrpDllNotificationList（内核数据结构）
❌ 需要写入一段 shellcode
❌ 要等目标加载 DLL 才触发（时机不可控）
```

**可检测性：低。** 这是目前比较新的思路。

---

### 11. AtomBombing

利用 Windows 的 Atom 表（全局字符串表）传递代码。

```
1. GlobalAddAtom 把 shellcode 存进 Atom 表
2. 在目标进程里 NtQueueApcThread 调 GlobalGetAtomName
3. Atom 内容被写入目标进程的栈
4. APC 第二次调用，执行栈上的代码
```

**留下什么**：

```
✅ 数据通过合法 API 传递
✅ 不分配新的可执行内存（栈本身可执行？需要验证）
❌ 两个 APC
❌ 栈上执行代码（DEP 可能拦）
```

**可检测性：中。** 现代 Windows 上栈不可执行，这个技术基本失效了。

---

## 四、可检测性总览

把上面所有信息汇总：

| 技术 | 新线程 | 新模块 | RWX | 非映像可执行 | 代码段哈希变 | 综合 |
|---|---|---|---|---|---|---|
| CreateRemoteThread+LoadLibrary | ❌ | ❌ | ❌ | ✅ | ✅ | **最差** |
| NtCreateThreadEx | ❌ | ❌ | ❌ | ✅ | ✅ | **差** |
| QueueUserAPC | ✅ | ❌ | ❌ | ✅ | ✅ | 中 |
| 线程劫持 | ✅ | ❌ | ❌ | ✅ | ✅ | **中低** |
| SetWindowsHookEx | ✅ | ❌ | ❌ | ✅ | ❌ | 差 |
| 反射式 | ❌ | ✅ | ❌ | ✅ | ✅ | 中 |
| **手工映射** | ❌ | ✅ | 可能 | ❌ | ✅ | **中低** |
| 模块踩踏 | ❌ | ✅ | ✅ | ✅ | ✅ | 中 |
| 进程镂空 | ✅ | ✅ | ❌ | ❌ | ✅ | 中 |
| DLL 通知回调 | ✅ | ✅ | ❌ | ❌ | ✅ | **低** |
| AtomBombing | ✅ | ✅ | ❌ | ❌ | ❌ | 已失效 |

（✅ = 规避了该项检测）

**要点**：

- **没有一项能规避所有检测。** 最关键的是「非映像可执行内存」——只要你的代码不在某个合法模块的映像范围内，它就是可疑的。
- 唯一能同时规避「新线程 + 非映像内存」的是**模块踩踏**（代码在映像内）+ **DLL 通知回调**（不起线程），但前者破坏代码段哈希，后者要 patch 内核数据结构。

---

## 五、为什么最终选了外部只读

看完这些技术，反过来理解 memkit 的设计：

| 检测项 | 手工映射 | 外部只读 |
|---|---|---|
| 新线程 | ❌ 有 | ✅ 无 |
| 新模块 | ✅ 无 | ✅ 无 |
| RWX 页 | 可能 | ✅ 无 |
| 非映像可执行页 | ❌ 有 | ✅ 无 |
| 代码段哈希 | ✅ 没变 | ✅ 没变 |
| **句柄** | 有 | **有（唯一）** |

外部只读**只有一项暴露**，而这一项可以通过 200ms 上限 + 权限掩码 + 读取预算压到很低。

注入**至少暴露两项**（非映像内存必然有），而且无法消除。

这就是"不注入"的技术依据，不是道德判断。

---

## 六、如果确实要注入：最佳组合

假设将来必须注入（需要调用游戏函数），推荐组合：

```
代码怎么进去：手工映射（memkit 已实现）
             ↓ 比反射式少一个"加载器特征"
怎么触发：   DLL 通知回调 或 线程劫持
             ↓ 比 CreateRemoteThread 少一个"新线程"
代码放哪：   模块踩踏到某个冷门模块
             ↓ 比私有映射少一个"非映像页"
```

三层都是中等风险，叠加起来仍然会暴露至少一项。

**没有"完全隐蔽"的注入。** 如果有人告诉你某个注入技术"完全无痕"，那是错的——只是反作弊还没实现对应的检测。

---

## 七、反作弊的检测能力对照

理解注入的前提是理解检测。常见手段：

| 检测手段 | 能发现什么 | 数据来源 |
|---|---|---|
| `EnumProcessModules` | 新模块 | PEB → Ldr |
| `NtQueryInformationThread` | 新线程、起始地址 | 线程表 |
| `VirtualQueryEx` 遍历 | RWX、非映像可执行页 | 虚拟内存管理 |
| 代码段哈希 | 打补丁、模块踩踏 | 读自己内存 |
| `NtQuerySystemInformation` | 谁持有我的句柄 | 系统句柄表 |
| ETW 事件 | `SetThreadContext`、线程创建 | `Microsoft-Windows-Threat-Intelligence` |
| `ObRegisterCallbacks` | 谁在打开我的句柄（内核级） | 内核回调 |

最后两项是最难绕的：**ETW 和内核回调都在内核侧，用户态无法规避。**

---

## 八、这个分支的定位

`research/injection` 分支**不用于生产**，用途是：

1. **知识储备** —— 理解攻击面，才知道防御的重点
2. **能力可行性验证** —— 需要时能快速搭出来
3. **对比实验** —— 用真实数据说明"为什么不注入"

代码层面：

```
src/stealth/manualmap.hpp    手工映射（7 阶段，已实现）
src/stealth/inject.hpp       APC + 线程劫持（已实现）
src/stealth/pebunlink.hpp    PEB 摘链（可选加固）
```

这三个文件在 `main` 上也有，但 `main.cpp` 从不调用它们。

**判据**：如果某天 `main.cpp` 开始调用它们，说明做了架构妥协——那时应该重新审视整个防护模型，而不是偷偷加一行代码。

---

## 九、实测数据（本机验证，非推断）

`tools/injprobe.cpp` 做了真实注入对照实验。方法：自己 `CreateProcess` 一个 sleeper 子进程，然后在注入前后按时间线采样它的状态。

### CreateRemoteThread

```
=== 自建目标 + 注入（thread）===
目标 pid = 21272
  [注入前]   模块=5 线程=2 RWX页=0 非映像可执行页=0

  shellcode = 28 字节
  注入 = 成功

  [+200ms]   模块=5 线程=3 RWX页=1 非映像可执行页=1
  [+600ms]   模块=5 线程=3 RWX页=1 非映像可执行页=1
  [+1200ms]  模块=5 线程=3 RWX页=1 非映像可执行页=1
  [+2400ms]  模块=5 线程=2 RWX页=1 非映像可执行页=1
```

### QueueUserAPC

```
=== 自建目标 + 注入（apc）===
目标 pid = 22280
  [注入前]   模块=5 线程=2 RWX页=0 非映像可执行页=0

  shellcode = 28 字节
  注入 = 成功

  [+200ms]   模块=5 线程=2 RWX页=1 非映像可执行页=1
  [+600ms]   模块=5 线程=2 RWX页=1 非映像可执行页=1
  [+1200ms]  模块=5 线程=2 RWX页=1 非映像可执行页=1
  [+2400ms]  模块=5 线程=2 RWX页=1 非映像可执行页=1
```

### 对比

| 指标 | CreateRemoteThread | QueueUserAPC |
|---|---|---|
| 模块数 | 5 → 5（不变） | 5 → 5（不变） |
| **线程数** | 2 → **3** | 2 → **2**（不变） |
| **RWX 页** | 0 → **1** | 0 → **1** |
| **非映像可执行页** | 0 → **1** | 0 → **1** |

**结论**：

1. **APC 是唯一不增加线程的方式** —— 这是它比 CreateRemoteThread 强的实测依据。
2. **两者都必然留下 RWX 页** —— 因为 shellcode 需要一个可写可执行的落点。
3. 线程在 +2400ms 时退出了（shellcode 里的 Sleep 结束），但 **RWX 页永远留着** —— 除非显式 `VirtualFreeEx`。
4. 模块数全程不变 —— 因为我们没走 `LoadLibrary`，这是手工映射/APC 相对 CreateRemoteThread+LoadLibrary 的优势。

**第 3 点很重要**：即使线程退出了，那块 RWX 内存还在。这就是为什么"注入一次就删掉 shellcode"是不够的——必须连内存一起释放。

---

## 十、踩坑记录（shellcode 层面）

写这段 shellcode 时连崩了四次目标进程。记录一下，都是真实教训：

### 坑 1：`call [rip+disp]` 的位移算错

```asm
FF 15 02 00 00 00    call qword ptr [rip+2]
```

**错了**。`rip` 指向**下一条指令**（也就是这条 6 字节指令的末尾）。如果目标地址就紧跟在这 6 字节后面，`disp` 应该是 `0`，不是 `2`。

改成 `mov rax, imm64 / call rax` 完全避免这个计算。

### 坑 2：忘了恢复栈

```asm
sub rsp, 0x28
call ...
; 忘了 add rsp, 0x28 就 ret
```

`ret` 会弹出错误的返回地址。表现：`0xC0000005`。

### 坑 3（最隐蔽）：用 ExitThread 收尾

```asm
xor ecx, ecx
call ExitThread
```

看着很合理，但会崩。原因：`ExitThread` 内部走**异常展开**（处理 TLS 回调等），而 `CreateRemoteThread` 创建的线程**没有注册 unwind 信息**，展开失败 → `0xC0000005`。

**正确做法**：平衡栈之后 `ret`，交给系统自己收尾。系统知道这个线程是从 `CreateRemoteThread` 起来的，会走 `RtlExitUserThread` 的正确路径。

### 坑 4：目标还没初始化完就注入

`CreateProcess` 之后立刻注入，目标还在 loader 阶段，注入会让它崩。

实测 **600ms 之后**才稳定。这个在 `injprobe.cpp` 里注释说明了。

### 坑 5：注入前对新建进程做重量级查询

`EnumProcessModules` / `VirtualQueryEx` 遍历新建进程会干扰它的初始化。

改成：
- 模块数用 `Toolhelp32` 快照（更轻）
- `VirtualQueryEx` 只在注入**之后**用

---

## 十一、这些数据的用途

回头看 memkit 的主路径（外部只读），用上面的数据对照：

| 检测项 | CreateRemoteThread | APC | **外部只读** |
|---|---|---|---|
| 线程数变化 | +1 | 不变 | **不变** |
| RWX 页 | +1 | +1 | **不变** |
| 非映像可执行页 | +1 | +1 | **不变** |
| 模块数变化 | 不变（未 LoadLibrary） | 不变 | **不变** |
| **句柄** | 有 | 有 | **有** |

**外部只读只有最后一行**。前四行全部是零。

这就是"不注入"的实测依据——不是因为道德，是因为**注入必然留下前四行中的至少两行**。
