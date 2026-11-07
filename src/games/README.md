# src/games/ —— 游戏层（main 分支为空）

这个目录在 `main` 上**故意是空的**。每个游戏一个子目录，各自在自己的分支里。

## 为什么隔离

框架负责「怎么安全地读内存」，游戏层负责「读哪里、读到的东西是什么意思」。

这两件事的变化频率差 100 倍：

| 层 | 什么时候变 |
|---|---|
| 框架（会话、句柄、加密、验证） | 几乎不变 |
| 游戏层（偏移、结构布局、坐标系） | 每次游戏版本更新 |

混在一起的话，每次游戏更新都会动到框架代码，commit 历史全是噪音，
而且没法判断某个改动是"框架 bug"还是"偏移过期"。

## 约定

### 依赖方向

```
src/games/<name>/  ──→  src/os/  src/common/
       ↑                    ↑
       └──── 单向，不可反向 ───┘
```

游戏层只能 include `os/` 和 `common/`。**不能** include `stealth/` 或 `input/`
——那些是框架的可选能力，游戏层用不到。

如果游戏层发现框架缺能力，做法是：
1. 在 `main` 上加这个能力
2. 游戏分支 rebase 到新的 `main`
3. 再用

不要直接在游戏分支里改框架文件。

### 命名

```
src/games/<name>/
├─ README.md      这个游戏特有的坑（坐标系、结构体、版本差异）
├─ <topic>.hpp    按关注点拆：投影、实体、界面…
└─ ...
```

全部 header-only。理由同框架：没有链接顺序问题，也没有跨模块的 ABI 风险。

### 编译开关

每个游戏一个 `MEMKIT_GAME_<NAME>` 选项，默认 `OFF`。

```cmake
option(MEMKIT_GAME_WOW "Build World of Warcraft support layer" OFF)
```

打开后：
- 自检额外跑这个游戏的断言
- `main.cpp` 里对应层被编译进来

这样 `main` 分支的二进制永远是"不含任何游戏代码"的干净版本。

## 已有分支

| 分支 | 目录 | 状态 |
|---|---|---|
| `game/wow-classic` | `src/games/wow/` | 逻辑完成，偏移表待填 |

## 从零开一个新游戏

见根 README 的「分支」一节。要点：

1. `git checkout main && git checkout -b game/<name>`
2. 建 `src/games/<name>/`、`profiles/`、`tables/<name>/`
3. 从 `examples/` 复制 profile 和偏移表骨架
4. CMake 里加 `MEMKIT_GAME_<NAME>` 选项
5. 自检里加 `#ifdef MEMKIT_GAME_<NAME>` 段落

## 一个反模式

**不要把游戏判断写进框架。**

```cpp
// ❌ 错：框架里出现游戏名
if (profile.name == "wow") { ... 特殊处理 ... }

// ✅ 对：框架只认字段和配置
if (profile.require_all_fields) { ... }
```

框架里出现任何游戏名，都会让这个仓库退化成"只能给一个游戏用"。
`main` 上搜索 `wow|warcraft` 应该 0 命中——这是每次提交前该跑的检查。
