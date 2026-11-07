// os/guardprobe.hpp —— 页陷阱探测与读取预算
//
// 解决两个真实缺口
// ================
//
// 一、guard page 探测
// -------------------
// 目标进程可以给自己的关键页装 PAGE_GUARD。这是外部扫描器最难察觉的陷阱。
//
// 实测确认（不是推断）：跨进程 NtReadVirtualMemory 读一个 guard 页返回
// **STATUS_PARTIAL_COPY (0x8000000D)**，got=0，读不到任何数据。
// 不是 STATUS_GUARD_PAGE_VIOLATION——那个是**进程内**访问才产生的。
//
// 而且这个状态是稳定的：guard 不会被这次读取清除，重复读仍返回同样错误。
// 所以只要第一次踩到，就永久拉黑这一页。
//
// 更阴的用法：在内存里布几十上百个"诱饵"地址，每个装 guard page 或者
// 指向未提交页。正常游戏自己不会读这些，谁读了谁就是外部扫描器。
//
// 我们能做的：
//   * 读返回 0x8000000D → 该页永久拉黑，永不再读
//   * 0x8000000D 也可能是"页部分有效"的正常情况，所以拉黑前
//     用 NtQueryVirtualMemory 确认是不是 guard / no-access
//   * 未提交页（MEM_FREE）也会返回类似错误，同样拉黑
//
// 二、读取预算
// ------------
// 一次快照读 20 个字段 = 20 次 NtReadVirtualMemory。
// 如果每 250ms 做一次，就是 80 次/秒。
// 人类玩家不会产生这种读取模式。
//
// 这里做令牌桶：
//   * 每秒 N 次读的额度
//   * 每次读消耗 1 个令牌
//   * 额度用完就延后（不是失败）
//
// 为什么不是硬性限速：
// 硬性限速会让读取变成固定节拍，反而成为特征。
// 令牌桶在额度内可以突发（模拟"看了一眼"），超出才延后。
#pragma once

#include <windows.h>

#include <cstdint>
#include <unordered_set>
#include <vector>

#include "common/hash.hpp"
#include "os/process.hpp"
#include "stealth/api.hpp"

namespace guard {

// 从 NTSTATUS 判断是否踩了 guard page
inline bool is_guard_violation(LONG status) noexcept {
    return status == static_cast<LONG>(0x80000001);
}

// 其他值得区分的状态
inline bool is_access_denied(LONG status) noexcept {
    return status == static_cast<LONG>(0xC0000022);
}
inline bool is_page_fault(LONG status) noexcept {
    return status == static_cast<LONG>(0xC0000005);
}
inline bool is_partial_copy(LONG status) noexcept {
    return status == static_cast<LONG>(0x8000000D);   // STATUS_PARTIAL_COPY
}

// ---------- 陷阱地址表 ----------
// 已知是陷阱的页，永久跳过
class TrapList {
public:
    void add(uintptr_t addr) { traps_.insert(page_of(addr)); }
    bool hit(uintptr_t addr) const { return traps_.count(page_of(addr)) != 0; }
    size_t size() const noexcept { return traps_.size(); }
    void clear() { traps_.clear(); }

    static uintptr_t page_of(uintptr_t addr) noexcept {
        return addr & ~static_cast<uintptr_t>(0xFFF);
    }

private:
    std::unordered_set<uintptr_t> traps_;
};

// ---------- 一次读的结果 ----------
enum class ReadOutcome : uint8_t {
    Ok = 0,
    GuardTrap = 1,       // 踩了 guard page（实测返回 0x8000000D）
    NotReadable = 2,     // 不可读（未提交/权限不足/跨页）
    Partial = 3,         // 只读到一部分
    BudgetExhausted = 4, // 额度用完，本次跳过
};

struct ReadResult {
    ReadOutcome outcome = ReadOutcome::NotReadable;
    LONG status = 0;
    size_t got = 0;

    bool ok() const noexcept { return outcome == ReadOutcome::Ok; }
};

// ---------- 读取预算（令牌桶）----------
//
// 默认值取"比正常玩家高一个量级，但不至于离谱"：
//   每秒 200 次读 —— 人类玩家几乎不产生读取，但我们的稳态是
//                    20 字段 × 4 次/秒 = 80 次/秒
//   突发 400 次   —— 允许短时间内读完整张表
//
// 这两个数需要按实际游戏调。核心是让"读取模式"看起来不像扫描器，
// 而不是完全隐藏读取（那做不到）。
class Budget {
public:
    Budget(double perSecond = 200.0, double burst = 400.0)
        : rate_(perSecond), cap_(burst), tokens_(burst) {
        last_ = os::now_ms();
    }

    // 尝试消耗 n 个令牌；不够返回 false
    bool try_consume(double n = 1.0) noexcept {
        refill();
        if (tokens_ < n) return false;
        tokens_ -= n;
        return true;
    }

    // 当前可用令牌
    double available() noexcept {
        refill();
        return tokens_;
    }

    void set_rate(double perSecond, double burst) noexcept {
        rate_ = perSecond;
        cap_ = burst;
        if (tokens_ > cap_) tokens_ = cap_;
    }

    // 统计
    uint64_t consumed() const noexcept { return consumed_; }
    uint64_t rejected() const noexcept { return rejected_; }

private:
    void refill() noexcept {
        const uint64_t now = os::now_ms();
        if (now <= last_) return;
        const double dt = static_cast<double>(now - last_) / 1000.0;
        last_ = now;
        tokens_ += dt * rate_;
        if (tokens_ > cap_) tokens_ = cap_;
    }

    double rate_;
    double cap_;
    double tokens_;
    uint64_t last_ = 0;
    uint64_t consumed_ = 0;
    uint64_t rejected_ = 0;
};

// ---------- 带保护的读取器 ----------
// 在 os::Session 之上包一层：查陷阱 → 查预算 → 读 → 记状态
class GuardedReader {
public:
    explicit GuardedReader(double perSecond = 200.0, double burst = 400.0)
        : budget_(perSecond, burst) {}

    ReadResult read(os::Session& s, uintptr_t addr, void* buf, size_t n) {
        ReadResult r;

        // 1. 已知陷阱直接跳过
        if (traps_.hit(addr)) {
            r.outcome = ReadOutcome::GuardTrap;
            return r;
        }

        // 2. 预算
        if (!budget_.try_consume(1.0)) {
            r.outcome = ReadOutcome::BudgetExhausted;
            return r;
        }

        // 3. 真正读（直接调 NtReadVirtualMemory 拿 status）
        const LONG st = raw_read(s, addr, buf, n, r.got);
        r.status = st;

        if (st >= 0) {
            r.outcome = r.got == n ? ReadOutcome::Ok : ReadOutcome::Partial;
            if (r.outcome == ReadOutcome::Partial) traps_.add(addr);
            return r;
        }

        // 4. 分类失败
        if (is_guard_violation(st)) {
            // 踩了 guard page：对方已经知道了。这一页永久拉黑。
            traps_.add(addr);
            r.outcome = ReadOutcome::GuardTrap;
            ++guardHits_;
            return r;
        }

        // 0x8000000D 有两种可能：
        //   a) 页是 guard / no-access / 未提交  → 陷阱，永久拉黑
        //   b) 读范围跨了页边界且后一页不可读  → 正常的部分读
        //
        // 必须区分。统一当陷阱会误杀合法的跨页读取；
        // 统一当部分读会让陷阱反复被踩（每次都通知对方）。
        if (is_partial_copy(st)) {
            if (is_trap_page(s, addr)) {
                traps_.add(addr);
                r.outcome = ReadOutcome::GuardTrap;
                ++guardHits_;
            } else {
                r.outcome = ReadOutcome::Partial;
            }
            return r;
        }

        r.outcome = ReadOutcome::NotReadable;
        return r;
    }

    // 查页属性，判断这个地址是不是陷阱页
    static bool is_trap_page(os::Session& s, uintptr_t addr) noexcept {
        os::Session::RegionInfo ri;
        if (!s.region(addr, ri)) {
            // 查不到区域信息本身就很可疑（未提交 / 非法地址）
            return true;
        }
        // MEM_COMMIT 才算正常提交；其余一律当陷阱
        if (ri.state != MEM_COMMIT) return true;

        // guard / no-access
        const DWORD p = ri.protect;
        if (p & PAGE_GUARD) return true;
        if (p == PAGE_NOACCESS) return true;

        return false;
    }

    const TrapList& traps() const noexcept { return traps_; }
    const Budget& budget() const noexcept { return budget_; }
    uint32_t guard_hits() const noexcept { return guardHits_; }

    // 自检：有没有踩过陷阱（踩过说明对方的防护生效了）
    bool clean() const noexcept { return guardHits_ == 0; }

private:
    // 直接调 ntdll，拿到精确 status。
    //
    // 为什么不复用 os::Session::Read：那个把 status 压成 bool，
    // 丢失了 GUARD_PAGE / PARTIAL_COPY 这些关键区分。
    static LONG raw_read(os::Session& s, uintptr_t addr, void* buf, size_t n, size_t& got) {
        using Fn = LONG(NTAPI*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
        static Fn fn = api::get<Fn>(api::mod::ntdll, hash::ascii("NtReadVirtualMemory"));
        if (!fn || !s.valid()) return static_cast<LONG>(0xC0000008);  // INVALID_HANDLE

        SIZE_T read = 0;
        const LONG st = fn(s.handle(), reinterpret_cast<PVOID>(addr), buf, n, &read);
        got = static_cast<size_t>(read);
        return st;
    }

    TrapList traps_;
    Budget budget_;
    uint32_t guardHits_ = 0;
};

}  // namespace guard
