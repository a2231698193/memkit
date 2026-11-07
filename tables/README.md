# tables/ —— 偏移表实例

框架本身不带任何偏移表。每个游戏一张，放在自己的分支里。

## 目录约定

```
tables/
├─ README.md              本文件（格式说明）
└─ <game>/
   ├─ template.txt        骨架：占位符 + 每个字段的定位提示
   ├─ <build>.txt         具体版本的偏移表（填好真实偏移）
   └─ README.md           可选：这个游戏的定位心得
```

例如：

```
tables/mygame/template.txt      ← 从 examples/ 复制，改字段名
tables/mygame/1.0.0.txt         ← 第一个可用版本
tables/mygame/1.0.1.txt         ← 小版本更新后新加一份
```

**为什么每版一份而不是就地改**：版本更新后旧表还有用——老客户端还在跑的时候
可以用旧表，而且 diff 能直接看出"这次更新动了哪几个偏移"。

## 格式

完整说明见根目录 README 的「核心概念」一节。最小示例：

```
!game      mygame
!build     1.0.0
!timestamp 0x63A1B2C3
!modsize   0x2A10000

# name            kind    type   offs                  check
player.hp        value   u32    0x2F1A3B0,0x10,0x2C0  inrange 1 200000
player.pos       value   vec3   0x2F1A3B0,0x10,0x30   -
```

## 怎么拿 TimeDateStamp

```powershell
$b = [IO.File]::ReadAllBytes("Game.exe")
$e = [BitConverter]::ToInt32($b, 0x3C)
[BitConverter]::ToUInt32($b, $e + 8)   # 十进制，转成 0x 形式
```

```python
import struct
d = open("Game.exe","rb").read()
e = struct.unpack_from("<I", d, 0x3C)[0]
print(hex(struct.unpack_from("<I", d, e + 8)[0]))
```

## 部署

偏移表加密后写到：

```
%LOCALAPPDATA%\<随机12位>\<name>.dat
```

随机目录名首次运行生成，存在 `HKCU\Software\Classes\CLSID\{00000000-0000-0000-0000-000000000000}\InprocServer32` 的 `ThreadingModel` 值里。

加密种子是 `cfgio::kTableSeed`（编译期常量）。改了种子旧文件就读不出来。

## 一定要写 check

没有 check 的偏移等于赌运气。版本更新后偏移错位，程序不会崩，只会读到垃圾然后基于垃圾决策——这类 bug 极难排查。

至少给每个 `value` 类型字段加一个 `inrange` 或 `ge`。


## 版本更新时怎么做

游戏小版本更新后，偏移通常会变几个。流程：

1. 复制上一个大版本的表：`cp 1.0.0.txt 1.0.1.txt`
2. 改 `!build` 和 `!timestamp`
3. 跑程序，`!strict 1` 模式下会停在第一个验证失败的字段
4. 只重新定位失败的那些，其余不动
5. 全绿后提交

这样每次更新只需处理真正变了的字段，不用整表重做。

## 反面例子：能跑就不管

最常见的错误是"程序能跑，不管了"。但偏移错位不会崩，只会读到垃圾：

```
hp 读到 0xCCCCCCCC  → 以为血满，其实在送
pos 读到 (0,0,0)    → 寻路算到原点，原地转圈
guid 读到上一个对象  → 攻击错误目标
```

所以 **check 不是可选项**。没有 check 的表，跑起来和跑对看起来一样。
