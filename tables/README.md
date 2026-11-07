# tables/ —— 偏移表实例

框架本身不带任何偏移表。每个游戏一张，放在自己的分支里。

## 目录约定

```
tables/
├─ README.md              本文件（格式说明）
└─ <game>/
   └─ <build>.txt         具体版本的偏移表
```

例如：

```
tables/mygame/1.0.0.txt
tables/mygame/1.0.1.txt
```

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
