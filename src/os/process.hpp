// os/process.hpp —— 短生命周期进程访问会话（框架核心）
//
// 设计约束（防检测的关键）：
//   1. 绝不长期持有目标进程句柄：单会话硬上限 200ms，到期自动关闭
//   2. 只申请最小权限：读用 PROCESS_VM_READ，查询用 QUERY_LIMITED_INFORMATION
//   3. 打开/读/关闭全部走 ntdll 原生 API，不产生 OpenProcess/ReadProcessMemory 导入
//   4. 会话对象不可拷贝，析构必关，避免异常路径泄漏句柄
#pragma once

#include <windows.h>
#include <winternl.h>

#include <cstddef>
#include <cstdint>

#include "common/hash.hpp"
#include "stealth/api.hpp"

namespace os {

using NtOpenProcessFn  = LONG(NTAPI*)(PHANDLE, ACCESS_MASK, PVOID, PVOID);
using NtCloseFn        = LONG(NTAPI*)(HANDLE);
using NtReadVmFn       = LONG(NTAPI*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
using NtQueryVmFn      = LONG(NTAPI*)(HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T);

inline NtOpenProcessFn nt_open_process() noexcept {
    static auto fn = api::get<NtOpenProcessFn>(api::mod::ntdll, hash::ascii("NtOpenProcess"));
    return fn;
}
inline NtCloseFn nt_close() noexcept {
    static auto fn = api::get<NtCloseFn>(api::mod::ntdll, hash::ascii("NtClose"));
    return fn;
}
inline NtReadVmFn nt_read_vm() noexcept {
    static auto fn = api::get<NtReadVmFn>(api::mod::ntdll, hash::ascii("NtReadVirtualMemory"));
    return fn;
}
inline NtQueryVmFn nt_query_vm() noexcept {
    static auto fn = api::get<NtQueryVmFn>(api::mod::ntdll, hash::ascii("NtQueryVirtualMemory"));
    return fn;
}

// 轻量计时：QPC 计数差转毫秒，不引入 <chrono>/pthread（MinGW 下会带进 OpenProcess 导入）
inline uint64_t ticks() noexcept {
    LARGE_INTEGER v{};
    QueryPerformanceCounter(&v);
    return static_cast<uint64_t>(v.QuadPart);
}

inline uint64_t ticks_per_ms() noexcept {
    static uint64_t f = [] {
        LARGE_INTEGER v{};
        QueryPerformanceFrequency(&v);
        return v.QuadPart ? static_cast<uint64_t>(v.QuadPart / 1000) : 1u;
    }();
    return f;
}

inline uint64_t now_ms() noexcept { return ticks() / ticks_per_ms(); }

// 一次批处理会话：Begin -> 若干 Read/Chain -> Close（或超时）
class Session {
public:
    static constexpr int64_t kMaxLifeMs = 200;

    Session() = default;
    ~Session() { Close(); }

    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;
    Session(Session&& o) noexcept : h_(o.h_), pid_(o.pid_), born_(o.born_) { o.h_ = nullptr; }
    Session& operator=(Session&& o) noexcept {
        if (this != &o) { Close(); h_ = o.h_; pid_ = o.pid_; born_ = o.born_; o.h_ = nullptr; }
        return *this;
    }

    // 映射场景需要 VM_OPERATION（分配/改权限/写），默认只给读权限
    static constexpr ACCESS_MASK kReadOnly = PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION;
    static constexpr ACCESS_MASK kWrite    = PROCESS_VM_READ | PROCESS_VM_WRITE |
                                             PROCESS_VM_OPERATION | PROCESS_QUERY_LIMITED_INFORMATION;

    bool Begin(DWORD pid, ACCESS_MASK mask = kReadOnly) {
        const auto open = nt_open_process();
        if (!open || pid == 0) return false;

        OBJECT_ATTRIBUTES oa{};
        oa.Length = sizeof(oa);
        CLIENT_ID cid{};
        cid.UniqueProcess = reinterpret_cast<HANDLE>(static_cast<uintptr_t>(pid));
        cid.UniqueThread = nullptr;

        HANDLE h = nullptr;
        const LONG st = open(&h, mask, &oa, &cid);
        if (st < 0 || !h) return false;

        h_ = h;
        pid_ = pid;
        born_ = now_ms();
        return true;
    }

    DWORD pid() const noexcept { return pid_; }
    HANDLE handle() const noexcept { return h_; }

    bool valid() const noexcept { return h_ != nullptr; }

    int64_t age_ms() const noexcept {
        if (!h_) return -1;
        return static_cast<int64_t>(now_ms() - born_);
    }

    bool alive() const noexcept { return h_ && age_ms() < kMaxLifeMs; }

    void Close() noexcept {
        if (!h_) return;
        const auto close = nt_close();
        if (close) close(h_);
        else CloseHandle(h_);
        h_ = nullptr;
        pid_ = 0;
    }

    // 单次读
    bool Read(uintptr_t addr, void* buf, size_t n) noexcept {
        if (!alive() || !buf || n == 0) return false;
        const auto rd = nt_read_vm();
        if (!rd) return false;
        SIZE_T got = 0;
        const LONG st = rd(h_, reinterpret_cast<PVOID>(addr), buf, n, &got);
        return st >= 0 && got == n;
    }

    template <class T>
    bool Read(uintptr_t addr, T& out) noexcept {
        return Read(addr, &out, sizeof(T));
    }

    template <class T>
    bool ReadPtr(uintptr_t addr, T*& out) noexcept {
        return Read(addr, &out, sizeof(out));
    }

    // 多级指针链：base 先解引用，再依次加偏移；out 为最终地址（最后一级之后再取值为调用方职责）
    bool Chain(uintptr_t base, const uintptr_t* offs, size_t n, uintptr_t& out) noexcept {
        uintptr_t cur = base;
        for (size_t i = 0; i < n; ++i) {
            if (!Read(cur, cur) || cur == 0) return false;
            cur += offs[i];
        }
        out = cur;
        return true;
    }

    // 区域信息（用于 AOB 扫描时判断可读页）
    struct RegionInfo {
        uintptr_t base = 0;
        size_t size = 0;
        ULONG state = 0;
        ULONG protect = 0;
    };
    bool region(uintptr_t addr, RegionInfo& out) noexcept {
        if (!alive()) return false;
        const auto q = nt_query_vm();
        if (!q) return false;

        struct MemoryBasicInformation {
            PVOID BaseAddress;
            PVOID AllocationBase;
            ULONG AllocationProtect;
            SIZE_T RegionSize;
            ULONG State;
            ULONG Protect;
            ULONG Type;
        } mbi{};

        const LONG st = q(h_, reinterpret_cast<PVOID>(addr), 0 /*MemoryBasicInformation*/,
                          &mbi, sizeof(mbi), nullptr);
        if (st < 0) return false;

        out.base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        out.size = mbi.RegionSize;
        out.state = mbi.State;
        out.protect = mbi.Protect;
        return true;
    }

private:
    HANDLE h_ = nullptr;
    DWORD pid_ = 0;
    uint64_t born_ = 0;
};

// 探针：仅判断目标是否存在、位数是否匹配（不读数据，也不留句柄）
inline bool probe(DWORD pid, bool* isWow64 = nullptr) {
    Session s;
    if (!s.Begin(pid, PROCESS_QUERY_LIMITED_INFORMATION)) return false;
    if (isWow64) {
        BOOL w = FALSE;
        *isWow64 = IsWow64Process(reinterpret_cast<HANDLE>(pid), &w) && w;
    }
    s.Close();
    return true;
}

}  // namespace os
