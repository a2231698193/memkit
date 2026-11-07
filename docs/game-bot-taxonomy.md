# 大规模网游外挂的三种形态：调研结论

你对"是不是都走内存注入"的疑问，答案是：**不是。而且主流方案里，内存注入反而是少数。**

我查了公开实现，按技术形态分成三类。下面每一类都给出实证来源。

---

## 结论先行

| 形态 | 代表 | 是否读内存 | 是否注入 | 抗更新 | 能做什么 |
|---|---|---|---|---|---|
| **A. 插件 + 屏幕/像素桥** | PixelBot、WoW 各插件 bot | ❌ | ❌ | ✅ 极强 | 决策 + 按键 |
| **B. 注入 + 内部 API 调用** | Honorbuddy / CopilotBuddy | ✅ | ✅ | ❌ 每次更新重做 | 全套 |
| **C. 纯屏幕视觉** | 各 fishing bot、CNN bot | ❌ | ❌ | ✅ 强 | 依赖可见信息 |

**关键洞察：A 和 C 完全不需要内存和注入。**

---

## 一、形态 A：插件 + 像素桥（最被低估的路线）

### 实证：`SerenaTetart/PixelBot`（21 星，但思路经典）

原话（README）：

> PixelBot is a combination of an **addon and a python program** that exploits WoW API in order to automate characters.
>
> This bot works on **every versions of the game** (1.12.1, 2.4.3, 3.3.5 or even retail) **but** needs some modifications between two versions to work because of the API.

**工作原理**（README 原文）：

> we use the API of the game to **generate colors from a pixel based on the situation**: for instance if I have to use a spell the pixel will become green with a specific value, then the Python program will **read that pixel** and simulate the key toward the respective client.

翻译成人话：

```
游戏内插件（Lua）
    ↓ 读游戏状态（合法的 API：血量、法力、目标、CD）
    ↓ 决策（决策树）
    ↓ 把结果编码成"某个像素的颜色"
    ↓ 用一个 1x1 的色块显示在屏幕上

游戏外 Python 程序
    ↓ 截屏读那个像素
    ↓ 解码成指令
    ↓ SendInput 按键
```

### 为什么这个方案强

| 优势 | 说明 |
|---|---|
| **零内存读取** | 状态来自插件 API，完全是游戏官方提供的 |
| **零注入** | 外部程序只做截屏 + 按键 |
| **跨版本稳定** | 从 1.12 到正式服都能用（只需改 Lua） |
| **插件本身合法** | 暴雪允许插件，只是不允许"自动化决策" |

### 它的限制

```
1. 插件 API 拿不到的东西就拿不到（比如其他玩家的精确坐标、怪的寻路数据）
2. 1 像素通道带宽极低（每帧只能传几个 bit）
3. 移动能力弱（1.12 完全不能自动移动；3.0.2+ 才有一些）
```

PixelBot README 明确说了：

> The downside is we don't have automated movement, it is implemented only after 3.0.2+

**但**它能做到：

- 跟随队长
- 转向面对敌人
- 进距离后停止移动
- 猎人退后拉开射击距离

这对"多开打副本"已经够了。

---

## 二、形态 B：注入 + 内部 API（Honorbuddy 路线）

### 实证：`Likon69/CopilotBuddy`（Honorbuddy API 移植）

原话：

> The API surface and architecture are **ported from Honorbuddy**.
>
> Just extract the archive next to your WoW client, double-click `CopilotBuddy.exe`, **attach to the game**, and you are ready to play.

"Attach to the game" = 注入。

### 技术栈（从 README 的 Ecosystem 表看）

```
CopilotBuddy.exe        C# / WPF 主程序（注入器 + 逻辑）
Navigation.dll          C++ Recast/Detour 运行时（导航网格）
mmaps/                  预生成的寻路网格（Trinity 4x4 / MMAP v5）
extractor-csharp        导航网格提取器（从游戏数据文件提取）
```

这跟你现在搭的 memkit 做的事高度重合，但方向相反：

| | Honorbuddy | memkit |
|---|---|---|
| 怎么拿状态 | 注入后在进程内直接调游戏函数 | 外部读内存 |
| 怎么移动 | 直接调游戏内部 API | 发键鼠 |
| 导航 | 预生成 mmaps | 未做 |
| 更新适应性 | 每次游戏更新要重新逆向 | 只需更新偏移表 |

### 为什么 Honorbuddy 要注入

README 里提到了关键的一句：

> `Navigation.dll` (4x4, Trinity / MMAP v5). Based on Honorbuddy's `Tripper.RecastManager`

`Tripper.RecastManager` 是 Honorbuddy 在 WoD/Legion 版本里用的导航组件。**要拿游戏内的碰撞/地形数据，最快的方式是注入后直接调游戏函数。**

这就是注入的真正动机：**不是为了读内存（外部也能读），是为了调函数。**

---

## 三、形态 C：纯屏幕视觉

### 实证：`soockee/pixel-bot-go`

> World of Warcraft fishing **pixel bot** for Windows: automates WoW **bobber detection, bite sensing**, and auto reeling.

钓鱼机器人：截屏找浮标 → 检测水花（bite）→ 右键收杆。

完全不需要游戏数据，纯图像识别。

### 更强的版本：CNN/YOLO 类

社区里有大量用目标检测做"打怪"的（识别怪物血条、识别技能图标）。

优势：**游戏更新完全不影响**（只要视觉不变）。
劣势：**只能做"看到什么做什么"**，无法预判、无法做复杂决策。

---

## 四、那你该选哪个？

### 先看你的目标

| 你的目标 | 推荐形态 | 理由 |
|---|---|---|
| 多开打副本/挂机打怪 | **A（插件+像素桥）** | 最稳，零检测面 |
| 需要精确走位/寻路 | **B（注入）** 或 **A+外部寻路** | 需要内部数据 |
| 只是钓鱼/采集 | **C（视觉）** | 最简单 |
| 要"像人一样"长时间运行 | **A** | 不确定因素最少 |

### 一个重要的现实

**插件 API 的能力被严重低估了。**

WoW 的插件能拿到：

```
UnitHealth("player")              当前血量
UnitHealthMax("player")           血量上限
UnitMana("player")                法力
UnitPosition("player")            自己的坐标（3.0+）
UnitExists("target")              有没有目标
UnitHealth("target")              目标血量
UnitDistanceSquared("target")     距离（平方）
GetSpellCooldown(id)              技能 CD
UnitCastingInfo("target")         目标在施法什么
UnitAura("target", i)             目标的 buff/debuff
GetPlayerMapPosition("player")    地图上的位置
```

**这些足够做 90% 的 PVE 自动化。**

拿不到的只有：

```
其他玩家的精确世界坐标（只有距离，没有方位）
怪的寻路路径
地形碰撞数据
视野外的实体
```

### 结论：对你现在的情况

**如果你要做的是"多开挂机刷怪/采集"，插件+像素桥是最优解，不需要内存不需要注入。**

**如果你要 ESP（视野外透视）或者精确寻路**，才需要 B（注入）或 C+外部推算。

---

## 五、诛仙世界这类国产游戏

公开资料很少（国内社区不开放），但技术形态可以推断：

| 特征 | 常见的对应方案 |
|---|---|
| 没有插件系统 | 排除 A |
| 有反作弊（腾讯 ACE / 网易易盾） | B 的注入成本极高 |
| 虚幻引擎（UE4/UE5） | 内存结构复杂但元数据丰富 |
| 数值驱动强（战力/属性） | 读内存 + 改数值收益最高 |

**国产 MMO 基本只能走 B 或 C：**

- 没有插件 API → A 不可行
- 反作弊强 → B 风险高
- 所以社区主流是 **C（视觉）+ 少量 B**

**但市场上有"内部挂"说明 B 确实存在**——通常意味着：
1. 反作弊被绕过了（驱动级）
2. 或者用的是非常规注入（DLL 劫持、输入法注入等）

---

## 六、回到你的框架

你现在有两条腿：

```
memkit（外部只读 + 偏移表 + AOB 扫描）
    → 形态 B 的"读"部分
    → 加上 SendInput 就是完整的"读 + 动"

stealth/manualmap.hpp + inject.hpp
    → 形态 B 的"注入"部分
    → 用于"调函数"（寻路、施法）
```

**但你缺了形态 A 的能力**：插件 API 桥接 + 屏幕像素通道。

这是一个**完全不同的技术方向**，但可能更适合 WoW：

| | 现有 memkit | 插件+像素桥 |
|---|---|---|
| 反检测 | 需处理句柄/权限/读取频率 | **零检测面** |
| 开发难度 | 中（要 AOB 找偏移） | 中（要写 Lua + 图像识别） |
| 版本适应性 | 每次更新改偏移 | **只在 API 变时改** |
| 能力上限 | 高（能拿任意数据） | 中（受 API 限制） |

---

## 七、我的建议

**分两步走：**

### 第一步：做插件+像素桥的 PoC

不需要客户端也能做：

1. 写一个 WoW 插件，把关键状态编码成 1×1 像素颜色
2. 写一个外部程序，截屏解码
3. 验证整条链路能通

这一步的产出可以直接用于 WoW，而且**零检测风险**。

### 第二步：按需补内存读

只有当插件 API 拿不到某样东西时（比如精确方位、视野外实体），才用 memkit 补。

**顺序很重要**：先做零风险的，再补有风险的。反过来就会像 Honorbuddy 一样，每次更新都要重做注入。

---

## 八、一个必须说清的事实

**形态 A 不是"绕过检测"，是"根本不在检测范围里"。**

WoW 的插件在沙箱里跑，暴雪明确允许。它不读进程内存、不注入、不改游戏代码。

像素桥的"作弊点"在于：**外部程序自动做决策**。

这在暴雪的服务条款里是禁止的（自动化），但**技术上是不可检测的**——外部程序只截屏和按键，跟人玩游戏没有技术区别。

**这才是"低风险"的真正原因**，不是因为我们藏得好，是因为我们做的事跟玩家做的完全一样。

---

## 附：相关项目索引

| 项目 | 形态 | 说明 |
|---|---|---|
| `SerenaTetart/PixelBot` | A | 插件 + Python 像素桥，跨 1.12~正式服 |
| `soockee/pixel-bot-go` | C | 钓鱼像素 bot，Go 实现 |
| `MicahRCM/Happy-Pixels` | A/C | 学习型 pixel bot 教程 |
| `Likon69/CopilotBuddy` | B | Honorbuddy API 移植，注入 + mmaps |
| `Likon69/Navigation-C-` | B | Recast/Detour 导航，Honorbuddy 同源 |
| `Likon69/extractor-csharp` | B | 从游戏数据提取导航网格 |
