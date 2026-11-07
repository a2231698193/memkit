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
#include "os/accessmask.hpp"
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

    // 掩码定义集中在 accessmask.hpp，避免各处自己拼
    static constexpr ACCESS_MASK kReadOnly = access::kPureRead;
    static constexpr ACCESS_MASK kWrite    = access::kMapNeeded;

    // 最近一次 Begin 的审计结果（诊断用）
    struct OpenAudit {
        bool attempted = false;
        bool passed = false;       // 权限掩码检查是否通过
        ACCESS_MASK requested = 0;
        ACCESS_MASK badBits = 0;
        const char* reason = "";
    };
    const OpenAudit& last_audit() const noexcept { return audit_; }

    // 打开目标进程。
    //
    // 关键：**在请求之前**校验权限掩码，不是开完再看。
    // 一旦 OpenProcess 成功，对方句柄表里就留下了你的权限请求，
    // 无法事后补救。误用 kWrite 做纯读取 = 明确暴露写入意图。
    //
    // allowMap: true 表示调用方确实要做手工映射（需要写权限）。
    //           默认 false，纯读取路径任何写权限位都会被拒。
    bool Begin(DWORD pid, ACCESS_MASK mask = kReadOnly, bool allowMap = false) {
        audit_ = OpenAudit{};
        audit_.attempted = true;
        audit_.requested = mask;

        // 第一道闸：权限掩码
        const auto verdict = access::check_readonly(mask, allowMap);
        audit_.passed = verdict.ok;
        audit_.badBits = verdict.badBits;
        audit_.reason = verdict.reason;
        if (!verdict.ok) {
            return false;   // 直接拒绝，连 OpenProcess 都不发
        }

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
    OpenAudit audit_{};
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
