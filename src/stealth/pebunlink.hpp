// stealth/pebunlink.hpp —— PEB 模块链表摘除
//
// 用途：手工映射进来的模块不会在 PEB 里（因为没走 LdrLoadDll），
// 但如果用 LoadLibrary 正常加载，就必须把它从三条链上摘掉：
//   InLoadOrderModuleList       —— NtQueryInformationProcess(ModuleInformation) 用
//   InMemoryOrderModuleList     —— EnumProcessModules / GetModuleHandle 用
//   InInitializationOrderLinks  —— 少数分析工具用
//
// 关键：只摘链不够。Windows 10 起还额外有：
//   * LdrpHashTable / LdrpModuleIndexBase —— 基于 RB 树的模块索引
//   * PEB->Ldr->EntryInProgress / LoadCount
// 只摘三条链的话，GetModuleHandleW 依然能找到（走 hash/树），
// 所以本项目的主路径是"根本不用 LoadLibrary"（见 manualmap.hpp）。
// 本文件属于可选加固，仅在确实需要正常加载后隐藏时使用。
//
// 另一个前提：摘链必须在目标进程内执行（改的是目标自己的 PEB）。
// 所以本文件是"在目标侧跑的 stub"，不是外部代码。
#pragma once

#include <windows.h>
#include <winternl.h>

#include <cstdint>
#include <cstring>

namespace ldrunlink {

// 与 ntdll 内部布局对齐
struct LdrEntryFull {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    void*      DllBase;
    void*      EntryPoint;
    ULONG      SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
};

inline void unlink_one(LIST_ENTRY* e) noexcept {
    if (!e || !e->Flink || !e->Blink) return;
    e->Blink->Flink = e->Flink;
    e->Flink->Blink = e->Blink;
    // 保留自环：某些 Windows 版本会校验链完整性，
    // 完全把指针清空反而更容易被 "遍历到一半就崩" 检测到
    e->Flink = e;
    e->Blink = e;
}

// 在自身（目标）进程内按模块基址摘除
// 返回 0 成功，负数失败
inline int unlink_self_module(void* moduleBase) noexcept {
#ifdef _WIN64
    const auto* peb = reinterpret_cast<const PEB*>(__readgsqword(0x60));
    if (!peb || !peb->Ldr) return -1;

    auto* ldrHead = const_cast<LIST_ENTRY*>(
        &reinterpret_cast<const PEB_LDR_DATA*>(peb->Ldr)->InMemoryOrderModuleList);

    auto* head = ldrHead;
    for (auto* it = head->Flink; it != head; it = it->Flink) {
        const auto* e = CONTAINING_RECORD(it, LdrEntryFull, InMemoryOrderLinks);
        if (e->DllBase != moduleBase) continue;

        // 三条链都摘
        unlink_one(const_cast<LIST_ENTRY*>(&e->InMemoryOrderLinks));
        unlink_one(const_cast<LIST_ENTRY*>(&e->InLoadOrderLinks));
        unlink_one(const_cast<LIST_ENTRY*>(&e->InInitializationOrderLinks));

        // 名字也清掉：有些检测直接读 BaseDllName 比对已知模块名，
        // 即使不在链上，内存里留着明文也可能是特征
        if (e->BaseDllName.Buffer && e->BaseDllName.MaximumLength) {
            std::memset(e->BaseDllName.Buffer, 0, e->BaseDllName.MaximumLength);
            const_cast<LdrEntryFull*>(e)->BaseDllName.Length = 0;
        }
        if (e->FullDllName.Buffer && e->FullDllName.MaximumLength) {
            std::memset(e->FullDllName.Buffer, 0, e->FullDllName.MaximumLength);
            const_cast<LdrEntryFull*>(e)->FullDllName.Length = 0;
        }
        return 0;
    }
    return -2;
#else
    (void)moduleBase;
    return -3;
#endif
}

// 一致性自检：遍历链，确认目标基址不在其中
// 注意：这只验证了"三条链"，没验证 hash 表和 RB 树。
// 完整的自检需要调 GetModuleHandleW，但那会引入新的行为特征，
// 所以线上不做主动调用，只在开发期 selftest 里用。
inline bool is_unlinked(void* moduleBase) noexcept {
#ifdef _WIN64
    const auto* peb = reinterpret_cast<const PEB*>(__readgsqword(0x60));
    if (!peb || !peb->Ldr) return false;

    const auto* head = reinterpret_cast<const LIST_ENTRY*>(
        &reinterpret_cast<const PEB_LDR_DATA*>(peb->Ldr)->InMemoryOrderModuleList);

    for (auto it = head->Flink; it != head; it = it->Flink) {
        const auto* e = CONTAINING_RECORD(it, LdrEntryFull, InMemoryOrderLinks);
        if (e->DllBase == moduleBase) return false;
    }
    return true;
#else
    (void)moduleBase;
    return false;
#endif
}

// ---------- 目标侧 stub：TLS 回调 + DllMain ----------
//
// 手工映射的最后一步。需要在目标进程里执行，方式见 inject.hpp。
//
// 参数布局（x64 调用约定：RCX = 参数块地址）：
//   +0x00  imageBase
//   +0x08  entryPoint (RVA 已加基址)
//   +0x10  tlsDirectory (RVA 已加基址，0 表示没有)
//   +0x18  flags (bit0 = DLL)
//
// 行为顺序（必须与正常加载器一致）：
//   1. 若 TlsDirectory 存在：对每个 AddressOfCallBacks 调用
//   2. 调 DllMain(hinstDLL, DLL_PROCESS_ATTACH, 0)
//
// 这里给的是 C 版本，实际注入时用汇编 stub 更可控（避免编译器
// 引入栈检查、SEH、TLS 使用等额外依赖）。
#pragma pack(push, 1)
struct StubParams {
    uint64_t imageBase;
    uint64_t entryPoint;
    uint64_t tlsDirectory;
    uint32_t flags;
    uint32_t reserved;
};
#pragma pack(pop)

using DllMainFn = BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID);
using TlsCallbackFn = void(NTAPI*)(PVOID, DWORD, PVOID);

inline void run_tls_callbacks(uint64_t tlsDir, uint64_t imageBase) {
    if (tlsDir == 0) return;

    // IMAGE_TLS_DIRECTORY64
    struct TlsDir {
        uint64_t StartAddressOfRawData;
        uint64_t EndAddressOfRawData;
        uint64_t AddressOfIndex;
        uint64_t AddressOfCallBacks;
        uint32_t SizeOfZeroFill;
        uint32_t Characteristics;
    };

    const auto* tls = reinterpret_cast<const TlsDir*>(tlsDir);
    if (!tls->AddressOfCallBacks) return;

    auto* cb = reinterpret_cast<TlsCallbackFn*>(tls->AddressOfCallBacks);
    for (size_t i = 0; i < 64 && cb[i]; ++i) {
        cb[i](reinterpret_cast<PVOID>(imageBase), DLL_PROCESS_ATTACH, nullptr);
    }
}

// 目标侧入口：返回 0 表示成功
extern "C" __declspec(noinline) uint32_t __stdcall map_stub(StubParams* p) {
    if (!p || !p->entryPoint) return 1;

    run_tls_callbacks(p->tlsDirectory, p->imageBase);

    const auto fn = reinterpret_cast<DllMainFn>(p->entryPoint);
    const BOOL ok = fn(reinterpret_cast<HINSTANCE>(p->imageBase), DLL_PROCESS_ATTACH, nullptr);
    return ok ? 0u : 2u;
}

}  // namespace ldrunlink
