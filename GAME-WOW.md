# game/wow-classic 分支

魔兽世界怀旧服的偏移表 + 游戏逻辑层。

框架部分（内存读取、会话管理、加密存储）完全继承 `main`，这个分支只加：

```
src/games/wow/            游戏逻辑（与框架解耦）
├─ w2s.hpp                投影 / 向量 / 视野锥
├─ entity.hpp             实体列表遍历 + 对象字段读取
└─ world.hpp              快照 → 语义对象（Player/Target/Camera）

profiles/
└─ wow-classic-era.txt    目标描述

tables/wow-classic-era/
└─ template.txt           偏移表骨架（全是占位符）
```

## 客户端变体

进程名与二进制都不同，偏移表不能通用：

| 客户端 | 进程名 | build 前缀 | 表名 |
|---|---|---|---|
| 经典旧世 Classic Era | `WowClassic.exe` | 1.15.x | `wow-classic-era` |
| 巫妖王怀旧 WotLK | `WowClassic.exe` | 3.4.x | `wow-classic-wotlk` |
| 正式服 Retail | `Wow.exe` | 11.x | `wow-retail` |

**注意前两个进程名完全相同**，靠 `!timestamp`（PE TimeDateStamp）区分，不能靠 exe 名。

## 构建

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
      -DMEMKIT_SELFTEST=ON -DMEMKIT_GAME_WOW=ON
cmake --build build
./build/selftest.exe
```

`MEMKIT_GAME_WOW=ON` 会让自检额外跑 67 项 WoW 断言（投影、向量、实体、世界模型）。

## 当前状态

| 模块 | 状态 |
|---|---|
| 投影数学 | ✅ 已测（中心/四角/背面拒绝/矩阵 sanity） |
| 向量与视野锥 | ✅ 已测（2D/3D 距离、纯高度差、FOV 边界） |
| 实体校验 | ✅ 已测（GUID 类型、血量、坐标范围） |
| 世界模型 | ✅ 已测（空快照不产生假 0、Suspect 不算已知） |
| 列表遍历器 | ⚠️ 已实现，**未经真实数据验证** |
| **真实偏移表** | ❌ **全是占位符，需要调试器定位** |

## 定位偏移的步骤

### 0. 前置

装好客户端，确认是哪个变体。工具：

- **Cheat Engine**（找数值最快）
- **x64dbg**（追指针链、看反汇编）
- **REA**（静态分析，找静态基址的引用点）

### 1. 找 player.guid（第一步）

GUID 是 64 位大整数，变化少，比血量好找。

```
CE 搜索：Unknown initial value → 8 字节
   切地图 / 重登（GUID 不变）
   在聊天框输入 /run print(UnitGUID("player"))
   把打印出来的十进制 GUID 拿去搜索
```

拿到地址后：右键 → 找出是什么访问了这个地址 → 看哪个指令是"结构体基址 + 固定偏移"。

### 2. 追到静态基址

对地址做指针扫描（CE 的 Pointer Scan）：

```
最大层级：5~7（WoW 的链通常 3~5 级）
最大偏移：0x2000
```

扫描结果里找**偏移稳定**的那条（重启游戏后偏移不变）。链的终点应该是 `WowClassic.exe+0x??????` 形式。

### 3. 填表并验证

```bash
# 编辑 tables/wow-classic-era/<build>.txt
player.guid  value  u64  0x静态偏移,0x中间偏移,0x最终偏移  ge 1
```

跑程序，看健康度：

```
[ OK ] 全部字段验证通过
      健康度 100%
```

如果不是 100%，`strict=1` 会直接停机，日志里能看到哪个字段失败。

### 4. 找 camera.matrix（做投影必须）

这是最难的一步。方法：

1. CE 里搜浮点数（矩阵元素是 float）
2. 转一下视角，搜"变了的"
3. 找到 16 个连续 float 的起始地址
4. 对起始地址做指针扫描

**关键陷阱**：矩阵有行主序/列主序两种布局。`wow::guess_major()` 可以自动判断，但需要两个已知坐标点做实测：

```cpp
// 用自己 + 目标两个点，看哪个序投影出来的落点在屏幕内
auto major = wow::guess_major(vm, playerPos, screen);
```

投影出来后画个框验证：站在目标旁边，框应该正好套在角色身上。如果框在脚下打转 90°，说明矩阵序反了。

### 5. 找 objects.* （最复杂，可最后做）

WoW 的实体列表不是连续数组。需要确认三件事：

```
objects.first      列表头 → 首条目
objects.next_off   条目内 "下一个" 指针偏移（链表）
objects.obj_off    条目内 "对象" 指针偏移
```

判断是链表还是数组：读列表头 + 偏移，看拿到的值是"指向下一条目的指针"还是"下一个对象本身"。

遍历器的保护：深度上限 2000、GUID 去重、逐条验证（血上限 > 0 才算有效）。

## 已知的坑

| 坑 | 说明 |
|---|---|
| 坐标轴含义 | `vec3` 读出来是 x/y/z，但 WoW 的 y 通常是高度。命名时注意 |
| GUID 类型位 | 高 16 位是类型标记，低位才是有效 ID |
| 血量多副本 | 客户端里可能有当前值/预测值/显示值三份，要读引擎权威值 |
| 进程名相同 | 经典旧世和巫妖王都是 `WowClassic.exe` |
| 版本频繁更新 | 小版本更新也会动偏移，每次更新都要重新核对 |

## 设计取舍

### 为什么每条偏移都要 check

没有 check 的偏移等于赌运气。偏移错位时程序不会崩，只会静默读垃圾然后基于垃圾决策——这类 bug 极难排查。详见根 README。

### 为什么 Unknown 不能变成 0

`alive()` 在血量未知时返回 `false`，而不是"血量 0"。因为"读不到"和"真的死了"是两回事，处理方式完全不同（前者重试，后者放弃）。

`hp_pct()` 在未知时返回 `-1.0f`，这个负值是个显式标记，业务层必须判断。

### 为什么 isDead 是方法不是成员

做成成员变量会导致「手动改 hp 后 isDead 不同步」——已经踩过一次，测试里固定了这个行为（`e.hp = 0; check(e.dead())`）。

## 下一步

1. 装客户端，确认变体
2. 按上面步骤 1→3 找到 player.guid / hp / pos
3. 用 REA 静态分析 `WowClassic.exe`，找静态基址的引用点（能加速步骤 2）
4. 步骤 4（camera）和 5（objects）可以晚做，先让基础字段跑通
