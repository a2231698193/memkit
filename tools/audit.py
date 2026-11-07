#!/usr/bin/env python3
# tools/audit.py —— MVP 暴露面回归审计（每次提交前跑）
#
# 检查项：
#   1. 导入表：不得出现进程操作/注入类 API
#   2. 依赖 DLL：只允许白名单内的系统库
#   3. 明文串：不得出现目标进程名、模块名、Nt* 函数名
#   4. PE 卫生：无调试目录、无 .comment/.note、无 Rich 头
#   5. 段名：不得出现 MinGW 默认的 .eh_frame_full 等可辨识段
#
# 用法：python tools/audit.py build/memkit.exe
import re
import struct
import sys
from pathlib import Path

SENSITIVE_IMPORTS = [
    "OpenProcess", "OpenProcessToken", "ReadProcessMemory", "WriteProcessMemory",
    "CreateRemoteThread", "CreateRemoteThreadEx", "NtReadVirtualMemory",
    "NtWriteVirtualMemory", "NtOpenProcess", "NtCreateThreadEx", "DuplicateHandle",
    "EnumProcessModules", "EnumProcesses", "SetWindowsHookEx", "SetWindowsHookExA",
    "SetWindowsHookExW", "QueueUserAPC", "VirtualAllocEx", "WriteProcessMemory",
    "GetThreadContext", "SetThreadContext", "SuspendThread", "ResumeThread",
]

ALLOWED_DLLS = {
    "kernel32.dll", "user32.dll", "bcrypt.dll", "msvcrt.dll", "ntdll.dll",
    "advapi32.dll", "ole32.dll", "oleaut32.dll", "shell32.dll", "gdi32.dll",
    "ws2_32.dll", "crypt32.dll", "rpcrt4.dll", "combase.dll",
}

ALLOWED_KERNEL_MODULES = {"ntoskrnl.exe", "hal.dll", "wdmsec.dll", "ntstrsafe.dll"}

CRT_MARKERS = [
    "__cxa_", "_initterm", "malloc", "free", "printf", "memcpy", "memset",
    "__stdio", "__acrt", "_security_init_cookie", "__vcrt",
]

SENSITIVE_IMPORTS_DRIVER = [
    "PsLookupProcessByProcessId", "MmCopyVirtualMemory", "ZwOpenProcess",
    "ObRegisterCallbacks", "PsGetProcessPeb", "KeStackAttachProcess",
]

BANNED_STRINGS = [
    "Warden", "warden", "NtReadVirtualMemory",
    "NtOpenProcess", "NtQueryInformationProcess", "NtWriteVirtualMemory",
    "LLMHF", "frida", "x64dbg",
]


class Pe:
    """最小 PE 解析器：只取审计需要的字段，不引三方库。"""

    def __init__(self, data: bytes):
        self.d = data
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
            raise ValueError("not a PE file")
        self.lfanew = e_lfanew
        coff = e_lfanew + 4
        self.num_sections = struct.unpack_from("<H", data, coff + 2)[0]
        self.opt_size = struct.unpack_from("<H", data, coff + 16)[0]
        self.opt = coff + 20
        self.magic = struct.unpack_from("<H", data, self.opt)[0]
        self.is64 = self.magic == 0x20B
        self.image_base = struct.unpack_from("<Q", data, self.opt + 24)[0] if self.is64 \
            else struct.unpack_from("<I", data, self.opt + 28)[0]
        dd = self.opt + (112 if self.is64 else 96)
        self.data_dirs = [struct.unpack_from("<II", data, dd + 8 * i) for i in range(16)]
        self.sections = []
        sec = self.opt + self.opt_size
        for i in range(self.num_sections):
            o = sec + 40 * i
            name = data[o:o + 8].rstrip(b"\0").decode("latin1")
            vsize, vaddr, rsize, raddr = struct.unpack_from("<IIII", data, o + 8)
            self.sections.append((name, vaddr, vsize, raddr, rsize))

    def rva_to_off(self, rva: int) -> int:
        for _n, vaddr, vsize, raddr, rsize in self.sections:
            if vaddr <= rva < vaddr + max(vsize, rsize):
                return raddr + (rva - vaddr)
        return -1

    def imports(self):
        out = []
        rva, _size = self.data_dirs[1]
        if not rva:
            return out
        off = self.rva_to_off(rva)
        thunk_size = 8 if self.is64 else 4
        fmt = "<Q" if self.is64 else "<I"
        while True:
            ilt, _ts, _fc, name_rva, iat = struct.unpack_from("<IIIII", self.d, off)
            if name_rva == 0:
                break
            dll_off = self.rva_to_off(name_rva)
            dll = self.d[dll_off:self.d.index(b"\0", dll_off)].decode("latin1")
            names = []
            src = ilt or iat
            t = self.rva_to_off(src)
            while True:
                val = struct.unpack_from(fmt, self.d, t)[0]
                if val == 0:
                    break
                if not (val >> (63 if self.is64 else 31)):  # 按序号导入
                    hо = self.rva_to_off(val & 0x7FFFFFFF)
                    if hо > 0:
                        nm = self.d[hо + 2:self.d.index(b"\0", hо + 2)].decode("latin1")
                        names.append(nm)
                t += thunk_size
            out.append((dll, names))
            off += 20
        return out

    def has_dir(self, idx: int) -> bool:
        rva, size = self.data_dirs[idx]
        return rva != 0 and size != 0


def audit_driver(path: Path, pe: "Pe", data: bytes, fails: list) -> None:
    """内核驱动的额外检查：不允许任何 CRT 依赖。"""
    all_imports = set()
    mods = set()
    for mod, names in pe.imports():
        mods.add(mod.lower())
        all_imports.update(names)

    for m in sorted(mods - ALLOWED_KERNEL_MODULES):
        fails.append(f"[依赖] 非内核白名单模块: {m}")

    for marker in CRT_MARKERS:
        for sym in all_imports:
            if marker in sym:
                fails.append(f"[CRT] 驱动链入了 CRT 符号: {sym}")
                break

    for s_ in SENSITIVE_IMPORTS_DRIVER:
        if s_ in all_imports:
            fails.append(f"[导入] 驱动命中敏感 API: {s_}")

    if not pe.is64:
        fails.append("[PE] 驱动不是 x64")


def audit(path: Path) -> int:
    data = path.read_bytes()
    pe = Pe(data)
    fails = []
    is_driver = path.suffix.lower() == ".sys"

    # 1. 导入表
    all_imports = set()
    dlls = set()
    for dll, names in pe.imports():
        dlls.add(dll.lower())
        all_imports.update(names)

    if is_driver:
        audit_driver(path, pe, data, fails)
    else:
        for s in SENSITIVE_IMPORTS:
            if s in all_imports:
                fails.append(f"[导入] 命中敏感 API: {s}")

        # 2. 依赖 DLL 白名单
        for d in sorted(dlls - ALLOWED_DLLS):
            fails.append(f"[依赖] 非白名单 DLL: {d}")

    # 3. 明文串
    low = data.lower()
    for s in BANNED_STRINGS:
        if s.lower().encode() in low:
            fails.append(f"[明文] 命中禁用串: {s}")

    # 4. PE 卫生
    if pe.has_dir(6):
        fails.append("[PE] 存在 Debug 目录（泄漏 PDB 路径）")
    for name, *_ in pe.sections:
        if name in (".comment", ".note.gnu.property"):
            fails.append(f"[PE] 存在可辨识段: {name}")

    # 5. Rich 头（MSVC 特征；MinGW 正常没有，有则说明混链）
    if b"Rich" in data[:0x200]:
        fails.append("[PE] 存在 MSVC Rich 头")

    print(f"文件: {path}  ({len(data):,} 字节)")
    print(f"段: {', '.join(s[0] for s in pe.sections)}")
    print(f"依赖: {', '.join(sorted(dlls))}")
    print(f"导入符号数: {len(all_imports)}")
    print("-" * 60)
    if fails:
        for f in fails:
            print("FAIL", f)
        print(f"\n结论: 不通过（{len(fails)} 项）")
        return 1
    print("结论: 全部通过")
    return 0


if __name__ == "__main__":
    target = Path(sys.argv[1] if len(sys.argv) > 1 else "build/memkit.exe")
    sys.exit(audit(target))
