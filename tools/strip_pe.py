#!/usr/bin/env python3
# tools/strip_pe.py —— 清除 PE 里的工具链指纹
#
# 处理三件事：
#   1. Rich 头（"Rich" 标记 + 加密的编译器版本/目标架构映射）
#      MSVC 会把它插在 DOS 头与 PE 头之间，是识别"这是 MSVC 编译的"的强特征。
#   2. Debug 目录项（数据目录 6）：RVA/Size 清零
#   3. Debug 记录本体（.rdata 里的 IMAGE_DEBUG_DIRECTORY + 后续数据）
#      MSVC 默认写 coffgrp 类型记录，内容是编译器参数摘要。
#
# 用法：python tools/strip_pe.py <file.exe|file.sys>
import struct
import sys
from pathlib import Path


def strip(path: Path) -> None:
    d = bytearray(path.read_bytes())
    changed = []

    # 1. Rich 头：从 DOS 头末尾到 "Rich"+key 全部清零
    rich = d.find(b"Rich", 0x40)
    if 0 < rich < 0x200:
        for j in range(0x80, rich + 8):
            d[j] = 0
        changed.append(f"rich@{rich:#x}")

    # 2. 定位可选头与数据目录
    e_lfanew = struct.unpack_from("<I", d, 0x3C)[0]
    opt = e_lfanew + 4 + 20
    magic = struct.unpack_from("<H", d, opt)[0]
    is64 = magic == 0x20B
    dd = opt + (112 if is64 else 96)

    # 3. Debug 目录
    rva, size = struct.unpack_from("<II", d, dd + 8 * 6)
    if rva or size:
        struct.pack_into("<II", d, dd + 8 * 6, 0, 0)
        changed.append("dirdbg")

    # 4. Debug 记录本体
    if rva and size:
        nsec = struct.unpack_from("<H", d, e_lfanew + 4 + 2)[0]
        optsize = struct.unpack_from("<H", d, e_lfanew + 4 + 16)[0]
        sec = opt + optsize
        for s in range(nsec):
            o = sec + 40 * s
            vsize, vaddr, rsize, raddr = struct.unpack_from("<IIII", d, o + 8)
            if vaddr <= rva < vaddr + max(vsize, rsize):
                off = raddr + (rva - vaddr)
                for k in range(size):
                    if off + k < len(d):
                        d[off + k] = 0
                changed.append(f"dbgrec@{off:#x}")
                break

    if changed:
        path.write_bytes(d)
        print(f"stripped {path.name}: {', '.join(changed)}")
    else:
        print(f"{path.name}: nothing to strip")


if __name__ == "__main__":
    for arg in sys.argv[1:]:
        strip(Path(arg))
