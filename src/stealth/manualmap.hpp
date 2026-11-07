// stealth/manualmap.hpp —— 手工映射（P3 核心）
//
// 目标：把一段 PE 映像放进目标进程并执行，全程不出现：
//   * LoadLibrary / LdrLoadDll 调用（模块不会进 PEB 的 InLoadOrder / InMemoryOrder 链）
//   * 目标进程内的新文件句柄（不是从磁盘映射，而是我们自己读进来再写过去）
//   * 新线程（用现有线程的 APC 或句柄劫持）
//   * RWX 页（分段设置权限：写时 RW，执行时 RX）
//
// 与"反射式 DLL 注入"的区别：反射注入会在目标进程内跑一段自己的 PE 加载器，
// 那段代码本身就是特征。这里把加载器全部留在外部进程，目标进程只接收
// 已重定位好的映像 + 几个必须由目标侧完成的小动作（TLS 回调、入口点）。
//
// 阶段划分（每步都有明确失败点，不允许半途而废）：
//   1. 读磁盘 PE、解析头和节表                —— 外部
//   2. NtAllocateVirtualMemory 分配 RW        —— 外部
//   3. 按节表在本地拼出完整映像               —— 外部
//   4. 处理基址重定位（DIR64）                —— 外部
//   5. 解析导入表、填 IAT                     —— 外部（需读目标模块导出表）
//   6. 写入目标内存（分块）                   —— 外部
//   7. 按节改权限（.text → RX，绝不留 RWX）   —— 外部
//   8. TLS 回调 + DllMain(DLL_PROCESS_ATTACH) —— 目标侧
//
// 第 5 步是最容易做错的地方：要解析目标进程里 ntdll/kernel32 的导出表，
// 但那些表在目标内存里，必须逐字节读回来。这里做了一版缓存，
// 同一个 (module, name) 只读一次。
#pragma once

#include <windows.h>
#include <winternl.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

#include "common/hash.hpp"
#include "os/process.hpp"
#include "os/scan.hpp"
#include "stealth/api.hpp"

namespace mmap {

// ---------- 最小 PE 解析（只支持 64 位 PE32+）----------
struct PeImage {
    std::vector<uint8_t> raw;
    uint64_t imageBase = 0;
    uint32_t sizeOfImage = 0;
    uint32_t sizeOfHeaders = 0;
    uint16_t numSections = 0;
    uint32_t entryRva = 0;
    uint32_t relocRva = 0;
    uint32_t relocSize = 0;
    uint32_t importRva = 0;
    uint32_t importSize = 0;
    uint32_t tlsRva = 0;
    uint32_t tlsSize = 0;
    uint16_t characteristics = 0;
    uint32_t sectionTableOff = 0;

    static constexpr uint16_t kDll = 0x2000;

    bool is_dll() const noexcept { return (characteristics & kDll) != 0; }

    bool parse(std::vector<uint8_t>&& bytes) {
        raw = std::move(bytes);
        if (raw.size() < sizeof(IMAGE_DOS_HEADER)) return false;

        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(raw.data());
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

        const size_t ntOff = static_cast<size_t>(dos->e_lfanew);
        if (ntOff + sizeof(IMAGE_NT_HEADERS64) > raw.size()) return false;

        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(raw.data() + ntOff);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
        if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return false;

        imageBase = nt->OptionalHeader.ImageBase;
        sizeOfImage = nt->OptionalHeader.SizeOfImage;
        sizeOfHeaders = nt->OptionalHeader.SizeOfHeaders;
        numSections = nt->FileHeader.NumberOfSections;
        entryRva = nt->OptionalHeader.AddressOfEntryPoint;
        characteristics = nt->FileHeader.Characteristics;

        const auto& dir = nt->OptionalHeader.DataDirectory;
        relocRva = dir[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        relocSize = dir[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        importRva = dir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        importSize = dir[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
        tlsRva = dir[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
        tlsSize = dir[IMAGE_DIRECTORY_ENTRY_TLS].Size;

        sectionTableOff = ntOff + sizeof(IMAGE_NT_HEADERS64);
        if (sectionTableOff + numSections * sizeof(IMAGE_SECTION_HEADER) > raw.size()) return false;

        return sizeOfImage > 0 && sizeOfHeaders > 0;
    }

    const IMAGE_SECTION_HEADER* sections() const noexcept {
        return reinterpret_cast<const IMAGE_SECTION_HEADER*>(raw.data() + sectionTableOff);
    }
};

// ---------- ntdll 内存原语 ----------
using NtAllocFn    = LONG(NTAPI*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
using NtFreeFn     = LONG(NTAPI*)(HANDLE, PVOID*, PSIZE_T, ULONG);
using NtProtectFn  = LONG(NTAPI*)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
using NtWriteVmFn  = LONG(NTAPI*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

inline NtAllocFn nt_alloc() noexcept {
    static auto fn = api::get<NtAllocFn>(api::mod::ntdll, hash::ascii("NtAllocateVirtualMemory"));
    return fn;
}
inline NtFreeFn nt_free() noexcept {
    static auto fn = api::get<NtFreeFn>(api::mod::ntdll, hash::ascii("NtFreeVirtualMemory"));
    return fn;
}
inline NtProtectFn nt_protect() noexcept {
    static auto fn = api::get<NtProtectFn>(api::mod::ntdll, hash::ascii("NtProtectVirtualMemory"));
    return fn;
}
inline NtWriteVmFn nt_write_vm() noexcept {
    static auto fn = api::get<NtWriteVmFn>(api::mod::ntdll, hash::ascii("NtWriteVirtualMemory"));
    return fn;
}

// ---------- 目标侧导出解析（必须逐字节从目标读）----------
class RemoteResolver {
public:
    explicit RemoteResolver(os::Session& s) : s_(s) {}

    // 目标进程内按模块名查基址（结果缓存，同一次映射只查一次）
    uint64_t module(const std::string& nameLower) {
        auto it = modCache_.find(nameLower);
        if (it != modCache_.end()) return it->second;

        // 用 Toolhelp 在外部查（不读目标 PEB，侵入性更低）
        std::wstring w;
        w.reserve(nameLower.size());
        for (char c : nameLower) w.push_back(static_cast<wchar_t>(c));

        const uint64_t base = os::module_base(s_.pid(), w);
        modCache_[nameLower] = base;
        return base;
    }

    // 按函数名解析 RVA 对应的绝对地址
    uint64_t by_name(uint64_t modBase, const std::string& fn) {
        if (modBase == 0) return 0;

        const std::string key = std::to_string(modBase) + "!" + fn;
        auto it = fnCache_.find(key);
        if (it != fnCache_.end()) return it->second;

        const uint64_t addr = resolve_name_uncached(modBase, fn);
        fnCache_[key] = addr;
        return addr;
    }

    // 按序号解析（少数库用序号导出）
    uint64_t by_ordinal(uint64_t modBase, uint16_t ordinal) {
        if (modBase == 0) return 0;
        const std::string key = std::to_string(modBase) + "#" + std::to_string(ordinal);
        auto it = fnCache_.find(key);
        if (it != fnCache_.end()) return it->second;

        const uint64_t addr = resolve_ord_uncached(modBase, ordinal);
        fnCache_[key] = addr;
        return addr;
    }

private:
    // 读目标内存（失败返回 false，调用方必须检查）
    bool read(uint64_t addr, void* buf, size_t n) {
        return s_.Read(static_cast<uintptr_t>(addr), buf, n);
    }

    template <class T>
    bool read_one(uint64_t addr, T& out) {
        return read(addr, &out, sizeof(T));
    }

    uint64_t resolve_name_uncached(uint64_t modBase, const std::string& fn) {
        IMAGE_DOS_HEADER dos{};
        if (!read_one(modBase, dos) || dos.e_magic != IMAGE_DOS_SIGNATURE) return 0;

        IMAGE_NT_HEADERS64 nt{};
        if (!read_one(modBase + static_cast<uint32_t>(dos.e_lfanew), nt)) return 0;
        if (nt.Signature != IMAGE_NT_SIGNATURE) return 0;

        const auto& dir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (dir.VirtualAddress == 0 || dir.Size == 0) return 0;

        IMAGE_EXPORT_DIRECTORY exp{};
        if (!read_one(modBase + dir.VirtualAddress, exp)) return 0;

        // 名字表：分批读，一次最多 512 项，避免超大导出表读爆会话
        constexpr uint32_t kBatch = 512;
        for (uint32_t base = 0; base < exp.NumberOfNames; base += kBatch) {
            const uint32_t cnt =
                (exp.NumberOfNames - base) < kBatch ? (exp.NumberOfNames - base) : kBatch;

            std::vector<uint32_t> names(cnt);
            std::vector<uint16_t> ords(cnt);
            if (!read(modBase + exp.AddressOfNames + base * 4, names.data(), cnt * 4)) return 0;
            if (!read(modBase + exp.AddressOfNameOrdinals + base * 2, ords.data(), cnt * 2)) {
                return 0;
            }

            for (uint32_t i = 0; i < cnt; ++i) {
                char nameBuf[128] = {};
                if (!read(modBase + names[i], nameBuf, sizeof(nameBuf) - 1)) continue;
                if (fn != nameBuf) continue;

                // 命中：取该序号对应的函数 RVA
                uint32_t funcRva = 0;
                if (!read_one(modBase + exp.AddressOfFunctions + ords[i] * 4, funcRva)) return 0;

                // 转发导出：RVA 落在导出目录范围内
                if (funcRva >= dir.VirtualAddress &&
                    funcRva < dir.VirtualAddress + dir.Size) {
                    return resolve_forward(modBase, funcRva, dir.VirtualAddress);
                }
                return modBase + funcRva;
            }
        }
        return 0;
    }

    uint64_t resolve_ord_uncached(uint64_t modBase, uint16_t ordinal) {
        IMAGE_DOS_HEADER dos{};
        if (!read_one(modBase, dos) || dos.e_magic != IMAGE_DOS_SIGNATURE) return 0;

        IMAGE_NT_HEADERS64 nt{};
        if (!read_one(modBase + static_cast<uint32_t>(dos.e_lfanew), nt)) return 0;

        const auto& dir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (dir.VirtualAddress == 0) return 0;

        IMAGE_EXPORT_DIRECTORY exp{};
        if (!read_one(modBase + dir.VirtualAddress, exp)) return 0;
        if (ordinal < exp.Base || ordinal - exp.Base >= exp.NumberOfFunctions) return 0;

        uint32_t funcRva = 0;
        if (!read_one(modBase + exp.AddressOfFunctions + (ordinal - exp.Base) * 4, funcRva)) {
            return 0;
        }
        return modBase + funcRva;
    }

    // 转发导出形如 "NTDLL.RtlAllocateHeap"，需要递归解析
    uint64_t resolve_forward(uint64_t modBase, uint32_t fwdRva, uint32_t exportDirRva) {
        (void)exportDirRva;
        char buf[256] = {};
        if (!read(modBase + fwdRva, buf, sizeof(buf) - 1)) return 0;

        std::string fwd(buf);
        const size_t dot = fwd.find('.');
        if (dot == std::string::npos) return 0;

        std::string dll = fwd.substr(0, dot);
        std::string fn = fwd.substr(dot + 1);
        if (dll.empty() || fn.empty()) return 0;

        // 补 .dll 后缀（导出表里可能省略）
        if (dll.size() < 4 || dll.compare(dll.size() - 4, 4, ".dll") != 0) dll += ".dll";

        for (auto& c : dll) {
            if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
        }

        const uint64_t target = module(dll);
        if (target == 0) return 0;

        if (!fn.empty() && fn[0] == '#') {
            return by_ordinal(target, static_cast<uint16_t>(std::atoi(fn.c_str() + 1)));
        }
        return by_name(target, fn);
    }

    os::Session& s_;
    std::unordered_map<std::string, uint64_t> modCache_;
    std::unordered_map<std::string, uint64_t> fnCache_;
};

// ---------- 映射结果 ----------
struct Mapped {
    uint64_t base = 0;
    uint32_t size = 0;
    uint32_t entryRva = 0;
    uint32_t tlsRva = 0;
    bool isDll = false;
};

enum MapErr : int {
    kOk = 0,
    kErrParse = -1,
    kErrAlloc = -2,
    kErrWrite = -3,
    kErrHeaders = -4,
    kErrSections = -5,
    kErrReloc = -6,
    kErrImport = -7,
    kErrProtect = -8,
};

// 步骤 2~7：全在外部完成
inline int map_image(os::Session& s, PeImage& pe, Mapped& out) {
    if (pe.raw.empty() || pe.sizeOfImage == 0) return kErrParse;

    // ---- 步骤 2：分配 RW（绝不用 RWX）----
    const auto alloc = nt_alloc();
    if (!alloc) return kErrAlloc;

    PVOID remoteBase = reinterpret_cast<PVOID>(pe.imageBase);  // 先试首选基址
    SIZE_T regionSize = pe.sizeOfImage;
    LONG st = alloc(s.handle(), &remoteBase, 0, &regionSize, MEM_RESERVE | MEM_COMMIT,
                    PAGE_READWRITE);
    if (st < 0 || !remoteBase) {
        remoteBase = nullptr;  // 首选被占，让系统挑（重定位会修正）
        regionSize = pe.sizeOfImage;
        st = alloc(s.handle(), &remoteBase, 0, &regionSize, MEM_RESERVE | MEM_COMMIT,
                   PAGE_READWRITE);
        if (st < 0 || !remoteBase) return kErrAlloc;
    }

    const uint64_t remote = reinterpret_cast<uint64_t>(remoteBase);
    out.base = remote;
    out.size = pe.sizeOfImage;
    out.entryRva = pe.entryRva;
    out.tlsRva = pe.tlsRva;
    out.isDll = pe.is_dll();

    // ---- 步骤 3：本地拼映像 ----
    std::vector<uint8_t> image(pe.sizeOfImage, 0);
    const size_t headerLen = pe.sizeOfHeaders < image.size() ? pe.sizeOfHeaders : image.size();
    if (headerLen > pe.raw.size()) return kErrHeaders;
    std::memcpy(image.data(), pe.raw.data(), headerLen);

    const auto* sec = pe.sections();
    for (uint16_t i = 0; i < pe.numSections; ++i) {
        const auto& sh = sec[i];
        if (sh.SizeOfRawData == 0 || sh.VirtualAddress == 0) continue;

        // 关键细节：SizeOfRawData 可能大于 VirtualSize（文件对齐填充），
        // 拷贝长度取两者较小值，否则会覆盖下一节
        const size_t n = sh.SizeOfRawData < sh.Misc.VirtualSize ? sh.SizeOfRawData
                                                                : sh.Misc.VirtualSize;
        const size_t dst = sh.VirtualAddress;
        if (dst + n > image.size()) continue;
        if (static_cast<size_t>(sh.PointerToRawData) + sh.SizeOfRawData > pe.raw.size()) {
            return kErrSections;
        }
        std::memcpy(image.data() + dst, pe.raw.data() + sh.PointerToRawData, n);
    }

    // ---- 步骤 4：重定位 ----
    const int64_t delta = static_cast<int64_t>(remote) - static_cast<int64_t>(pe.imageBase);
    if (delta != 0 && pe.relocRva != 0 && pe.relocSize != 0) {
        size_t off = pe.relocRva;
        const size_t end = off + pe.relocSize;
        if (end > image.size()) return kErrReloc;

        while (off + sizeof(IMAGE_BASE_RELOCATION) <= end) {
            const auto* blk = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(image.data() + off);
            if (blk->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) break;

            const uint32_t count =
                (blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            const auto* entries = reinterpret_cast<const WORD*>(
                image.data() + off + sizeof(IMAGE_BASE_RELOCATION));

            for (uint32_t j = 0; j < count; ++j) {
                const WORD type = entries[j] >> 12;
                const WORD rvaOff = entries[j] & 0x0FFF;
                const size_t patch = blk->VirtualAddress + rvaOff;

                if (type == IMAGE_REL_BASED_DIR64) {
                    if (patch + sizeof(uint64_t) > image.size()) continue;
                    auto* p = reinterpret_cast<uint64_t*>(image.data() + patch);
                    *p = static_cast<uint64_t>(static_cast<int64_t>(*p) + delta);
                }
                // IMAGE_REL_BASED_ABSOLUTE 是填充项，跳过
            }
            off += blk->SizeOfBlock;
        }
    }

    // ---- 步骤 5：填 IAT ----
    if (pe.importRva != 0 && pe.importSize != 0) {
        RemoteResolver rr(s);
        size_t off = pe.importRva;
        const size_t end = off + pe.importSize;
        if (end > image.size()) return kErrImport;

        while (off + sizeof(IMAGE_IMPORT_DESCRIPTOR) <= end) {
            const auto* desc =
                reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(image.data() + off);
            if (desc->Name == 0) break;

            const char* dllName = reinterpret_cast<const char*>(image.data() + desc->Name);
            std::string dllLower(dllName);
            for (auto& c : dllLower) {
                if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
            }

            const uint64_t modBase = rr.module(dllLower);
            if (modBase == 0) return kErrImport;

            const uint32_t intRva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk
                                                             : desc->FirstThunk;
            size_t t = intRva;
            size_t iat = desc->FirstThunk;

            for (;;) {
                if (t + 8 > image.size() || iat + 8 > image.size()) break;
                const uint64_t thunk = *reinterpret_cast<uint64_t*>(image.data() + t);
                if (thunk == 0) break;

                uint64_t resolved = 0;
                if (thunk & (1ull << 63)) {
                    resolved = rr.by_ordinal(modBase, static_cast<uint16_t>(thunk & 0xFFFF));
                } else {
                    const size_t nameOff = static_cast<size_t>(thunk & 0x7FFFFFFF);
                    if (nameOff + 2 >= image.size()) return kErrImport;
                    const char* fnName = reinterpret_cast<const char*>(image.data() + nameOff + 2);
                    resolved = rr.by_name(modBase, std::string(fnName));
                }

                if (resolved == 0) return kErrImport;
                *reinterpret_cast<uint64_t*>(image.data() + iat) = resolved;
                t += 8;
                iat += 8;
            }
            off += sizeof(IMAGE_IMPORT_DESCRIPTOR);
        }
    }

    // ---- 步骤 6：分块写入 ----
    const auto wr = nt_write_vm();
    if (!wr) return kErrWrite;

    constexpr size_t kChunk = 0x10000;
    for (size_t written = 0; written < image.size(); written += kChunk) {
        const size_t n = (image.size() - written) < kChunk ? (image.size() - written) : kChunk;
        SIZE_T got = 0;
        if (wr(s.handle(), reinterpret_cast<PVOID>(remote + written), image.data() + written, n,
               &got) < 0 ||
            got != n) {
            return kErrWrite;
        }
    }

    // ---- 步骤 7：按节改权限 ----
    const auto prot = nt_protect();
    if (!prot) return kErrProtect;

    for (uint16_t i = 0; i < pe.numSections; ++i) {
        const auto& sh = sec[i];
        if (sh.VirtualAddress == 0 || sh.Misc.VirtualSize == 0) continue;

        const DWORD ch = sh.Characteristics;
        DWORD newProt = PAGE_READONLY;
        if ((ch & IMAGE_SCN_MEM_EXECUTE) && (ch & IMAGE_SCN_MEM_WRITE)) {
            newProt = PAGE_EXECUTE_READWRITE;  // 极少数节真的需要，保留
        } else if (ch & IMAGE_SCN_MEM_EXECUTE) {
            newProt = PAGE_EXECUTE_READ;
        } else if (ch & IMAGE_SCN_MEM_WRITE) {
            newProt = PAGE_READWRITE;
        }

        PVOID addr = reinterpret_cast<PVOID>(remote + sh.VirtualAddress);
        SIZE_T sz = sh.Misc.VirtualSize;
        ULONG old = 0;
        if (prot(s.handle(), &addr, &sz, newProt, &old) < 0) return kErrProtect;
    }

    return kOk;
}

// 撤销：映射失败时清掉远端内存，不留半成品（半成品是最明显的特征）
inline void unmap_image(os::Session& s, const Mapped& m) {
    if (m.base == 0) return;
    const auto fr = nt_free();
    if (!fr) return;
    PVOID addr = reinterpret_cast<PVOID>(m.base);
    SIZE_T sz = 0;
    fr(s.handle(), &addr, &sz, MEM_RELEASE);
}

}  // namespace mmap
