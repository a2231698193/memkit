# memkit

外部进程内存读取框架。**不注入、不写目标内存、不发输入**——只做只读采集。

设计目标是可复用：框架本身不认识任何具体游戏，换目标 = 换一份 profile + 换一张偏移表。

```
依赖: advapi32 / bcrypt / kernel32 / msvcrt / user32
敏感导入: 0（OpenProcess / ReadProcessMemory / CreateRemoteThread / SetWindowsHookEx 全部不出现）
自检: 439 项断言
```

## 为什么是纯读取

外部读取的三条硬约束决定了整个架构：

| 约束 | 后果 |
|---|---|
| 不注入 | 目标进程的模块列表、线程列表、内存页全都是干净的 |
| 不写 | 目标内存哈希不变，完整性扫描查不出任何东西 |
| 不发输入 | 不碰任何输入栈，不存在注入标记问题 |

唯一的暴露面是**句柄**。所以 `os::Session` 有 200ms 硬上限，批处理完立刻 `NtClose`。

`os/handles.hpp` 可以在任意时刻自证：枚举全系统句柄表，确认自己没有持有目标进程句柄。

## 架构

```
业务逻辑（只认字段名）
      ↓
os/gamestate.hpp    快照 + 变更检测
      ↓
os/resolve.hpp      地址解析 + 读值 + 验证
      ↓
os/schema.hpp       偏移表（唯一随版本变的东西）
      ↓
os/config_io.hpp    加密存储
      ↓
os/process.hpp      NtReadVirtualMemory，200ms 会话
```

### 目录

```
src/
├─ common/    hash  obf  rnd  ringlog  cfg
├─ os/        process  handles  sched  task  scan
│             schema  resolve  gamestate  config_io  profile
│             scanpattern（AOB 扫描）  guardprobe（陷阱/预算）
│             accessmask（权限掩码闸门）
├─ stealth/   api  antidebug  ident  manifest
│             manualmap  inject  pebunlink      攻击能力，主路径不用
├─ input/     backend  u32  driver  driver_proto  hookprobe
├─ ipc/       channel
├─ games/     ← 空（main 分支不含任何游戏代码）
└─ app/       main  selftest  wrap_stub
driver/       可选内核驱动（默认不构建）
tables/       偏移表实例（按游戏分目录）
profiles/     ← 空（main 分支不含）
examples/     格式示例（profile + 偏移表）
tools/        audit  strip_pe  实测探针
```

## 核心概念

### 偏移表 = 唯一会随版本变的东西

隔离成一层以后，版本更新只改一个文本文件，框架代码一行不动。

```
!game      mygame
!build     1.0.0
!timestamp 0x63A1B2C3

# name                kind    type   offs                     check
player.hp            value   u32    0x2F1A3B0,0x10,0x2C0     inrange 1 200000
player.pos           value   vec3   0x2F1A3B0,0x10,0x30      -
target.guid          value   u64    0x2F1A3B0,0x0             ge 0
```

`offs` 展开语义：

```
0x2F1A3B0,0x10,0x2C0 表示

  p = moduleBase + 0x2F1A3B0
  p = *(void**)p + 0x10
  p = *(void**)p + 0x2C0
  → p 是 hp 地址
```

第一项相对模块基址，后续每项都是「解引用 + 加偏移」。

**kind**：`chain`（只解析地址）/ `value`（解析 + 读值）/ `offset`（单级）

**type**：`u8` `u16` `u32` `u64` `i32` `f32` `f64` `vec3`

**check**：`-` / `eq N` / `ne N` / `le N` / `ge N` / `inrange A B`

### 每条偏移必须带验证

这是整个设计里最重要的一条。版本更新后偏移错位，程序**不会崩**，只会静默读垃圾然后基于垃圾做决策：

| 错位后读到 | 后果 |
|---|---|
| `hp = 0xCCCCCCCC` | 以为快死了，疯狂喝药 |
| `hp = 0`（其实读失败） | 以为死了，放弃战斗 |
| `guid = 随机值` | 攻击错误目标 |
| `pos = (0,0,0)` | 寻路到原点，原地转圈 |

三种状态语义必须区分：

| 状态 | 含义 | 该怎么做 |
|---|---|---|
| `Present` | 读到且验证通过 | 正常用 |
| `Suspect` | 读到了但值不合理 → **偏移错位** | 停机报警 |
| `Unknown` | 读不到 → 链断/会话失败 | 重试 |

### 快照保证一致性

一次快照里所有字段来自同一批 Session。不能一半是 3 秒前的血量、一半是当前血量。

`diff()` 只报告变了的东西，业务层不用每帧比全部字段。

### 缓存

多级链的中间结果在运行期稳定。稳态下每字段只需 **1 次读**（读值），而不是 N 次。

失效条件：值读失败 / 断言失败 / 模块基址变化 / pid 变化。

### 目标由 profile 决定

框架代码里没有任何游戏名：

```
!name   mygame
!exe    Game.exe
!module Game.exe
!table  mygame
!poll   500
!jitter 120
!strict 0

watch  player.hp
watch  player.pos
```

换游戏 = 换 profile + 换偏移表。

## 构建

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

自检：

```bash
cmake -S . -B build -G Ninja -DMEMKIT_SELFTEST=ON
cmake --build build && ./build/selftest.exe
```

审计（每次提交前必跑，任一失败返回非零）：

```bash
py -3 tools/audit.py build/memkit.exe
```

可选：

```bash
-DMEMKIT_BUILD_PROBES=ON    # 实测探针（rawspy / llspy / hookdetect）
-DMEMKIT_BUILD_DRIVER=ON    # 内核驱动（需要 WDK）
```

## 防检测基础设施

| 手段 | 位置 |
|---|---|
| 编译期字符串加密 | `common/obf.hpp` |
| PEB + 导出表哈希解析（零静态导入） | `stealth/api.hpp` |
| 反调试 / 反分析器 | `stealth/antidebug.hpp` |
| 名称随机化（互斥体/管道/实例） | `stealth/ident.hpp` |
| 短会话 + 句柄审计 | `os/process.hpp` `os/handles.hpp` |
| 链接期敏感符号拦截 | `app/wrap_stub.cpp` |
| 配置文件加密 + 随机目录 | `os/config_io.hpp` |
| PE 工具链指纹清理 | `tools/strip_pe.py` |

### 链接期符号拦截

MinGW 的 `libwinpthread` 通过 `sched.o` / `thread.o` 会把 `OpenProcess`、`DuplicateHandle`、`SuspendThread`、`ResumeThread`、`Get/SetThreadContext` 带进导入表——业务代码一行没调也会出现。

`app/wrap_stub.cpp` 用 `-Wl,--wrap=__imp_<name>` 把这些引用重定向到「**运行时从 kernel32 导出表解析真实函数再转发**」的桩。既消除静态导入，又保持语义 100% 一致。

注意：桩函数里不能有局部静态变量——`__cxa_guard_acquire` 用的是被包装的 pthread 锁，会自死锁。

## 实测结论（决定架构的那几条）

用 `tools/` 里的探针在本机实测，不是猜的：

| 问题 | 答案 |
|---|---|
| `SendInput` 会被 Raw Input 看到标记吗 | **不会**。`RAWKEYBOARD`/`RAWMOUSE` 结构里没这个字段 |
| `SendInput` 会被低级钩子看到标记吗 | **会**。`LLKHF_INJECTED=1` |
| `InjectSyntheticPointerInput` 能替代吗 | **不能**。`PT_MOUSE` 是保留参数（err=87），只支持 TOUCH/PEN |
| 全局钩子能提前探测吗 | 可以，时序侧信道：每钩子约 20us（实测 158→178us） |
| 纯内存需要驱动吗 | **不需要**。`lsass` 那种 PPL 才需要 |

复现命令：

```bash
./build/probe_rawspy.exe sendinput
./build/probe_llspy.exe
./build/probe_hookdetect.exe
```

## 已验证（439 项断言）

| 能力 | 验证方式 |
|---|---|
| 偏移表序列化往返 | 二次序列化**逐字节一致** |
| 6 种验证断言 | 边界全覆盖 |
| 多版本注册表 | 按时间戳 / build 匹配 |
| 值解码 | u8/16/32/64, i32, f32, f64, vec3 |
| 多级链解析 | 实测 `base+0x3C → e_lfanew` |
| 缓存稳定性 | 二次读缓存大小不变 |
| 偏移错位检测 | 故意指错位置，检出 `Suspect` |
| 断链检测 | 越界二级指针，检出 `address_ok=false` |
| 快照一致性 + 变更检测 | 含 `becameValid` / `becameInvalid` |
| 加密存储往返 | 密文不含明写 |
| profile 解析 + 钳制 | 边界值全测 |
| 句柄审计 | 持有/释放/伪句柄全测 |
| AOB 特征码扫描 | 三种写法解析一致 + 唯一性拒绝 + disp 解析地址可读 |
| 页陷阱探测 | 实测 guard/NOACCESS/未提交 均判定为陷阱，正常区零误判 |
| 读取预算 | 令牌桶容量/恢复/联动全测 |
| 权限掩码闸门 | 纯读取只给 VM_READ+QUERY_LIMITED；写/注入类位请求前拒绝 |
| IPC 帧协议 | 正反向 + 大载荷 + 超限拒绝 |
| 驱动协议布局 | `static_assert` 锁死 + 无驱动优雅失败 |
| 手工映射错误路径 | 8 种错误码 |

## 待扩展（main 分支）

| 项 | 说明 |
|---|---|
| `Mat4` / `Vec2` 类型 | `game/wow-classic` 已实现，尚未回合 main。main 上 `VType` 只有 `vec3` 及以下 |
| `Kind::Scan` 接进偏移表 | 扫描器已实现（`os/scanpattern.hpp`，42 项断言）。缺的是让 `Resolver` 识别 `scan` 类型字段、启动时现算偏移 |
| 容器遍历 | 抽象层没有容器概念。实体列表遍历在游戏分支各自实现 |
| 指针链批量解析 | 当前逐字段走链，可以合并成一次批处理减少往返 |

合回 main 的判据：**多个游戏分支都需要**。只有一个游戏用的东西留在分支里。

## 分支

| 分支 | 内容 | 断言 |
|---|---|---|
| `main` | 通用框架，零游戏特定内容 | 439 |
| `game/wow-classic` | 魔兽世界怀旧服层（`src/games/wow/` + profile + 偏移表骨架） | 407 |

约定：

- `main` 的 **源码**（`src/` `tools/`）里搜索 `wow|warcraft` 必须 0 命中。
  文档里出现分支名是合法的——文档的作用就是描述分支
- 游戏分支从 `main` 拉出，只加 `src/games/<name>/`、`profiles/`、`tables/<name>/`
- 框架改动先落 `main`，再 rebase 到各游戏分支
- 多个游戏分支都需要的改动才回合 `main`

### 游戏分支怎么开

```bash
git checkout main
git checkout -b game/<name>

# 加这些，别动 src/ 下已有的框架文件
mkdir -p src/games/<name> profiles tables/<name>
cp examples/profile-example.txt profiles/<name>.txt
cp examples/table-example.txt   tables/<name>/template.txt

# 编译时打开对应开关
cmake -S . -B build -DMEMKIT_GAME_<NAME>=ON
```

`src/games/<name>/` 只允许 include `os/` `common/`，不允许反向依赖。
如果发现框架缺东西，改成框架能力后再回 `main`。

## 免责

仅用于本机、自有环境下的技术研究与自动化测试。