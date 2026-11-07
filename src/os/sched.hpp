// os/sched.hpp —— 批处理会话调度器（防检测的节流核心）
//
// 规则：
//   * 任意时刻最多 1 个目标句柄存活
//   * 每批任务共享一个 Session，批结束立刻 Close
//   * 批与批之间插入幂律长尾停顿，避免固定周期
//   * 会话超时（>200ms）未关闭则强制关闭并记录一次"泄漏事件"
#pragma once

#include <windows.h>

#include <cstdint>
#include <vector>

#include "common/rnd.hpp"
#include "common/ringlog.hpp"
#include "os/handles.hpp"
#include "os/process.hpp"
#include "os/task.hpp"

namespace os {

class Scheduler {
public:
    struct Stats {
        uint32_t batches = 0;
        uint32_t forced_closes = 0;
        uint32_t max_life_ms = 0;
        uint64_t total_hold_us = 0;
    };

    explicit Scheduler(DWORD pid) noexcept : pid_(pid) {}

    // 执行一批读取任务；fn 签名 bool(Session&)
    template <class Fn>
    bool run_batch(Fn&& fn) {
        Session s;
        if (!s.Begin(pid_)) {
            RLOG(Warn, rlog::kEvSessionBegin, 1, pid_);
            return false;
        }

        const uint64_t t0 = ticks();
        const bool ok = fn(s);

        const uint64_t held = ticks() - t0;
        const uint64_t perMs = ticks_per_ms() ? ticks_per_ms() : 1;
        stats_.total_hold_us += held * 1000ull / perMs;
        const uint32_t ms = static_cast<uint32_t>(held / perMs);
        if (ms > stats_.max_life_ms) stats_.max_life_ms = ms;

        if (!s.alive()) {
            ++stats_.forced_closes;
            RLOG(Warn, rlog::kEvSessionTimeout, 1, ms);
        }
        s.Close();
        ++stats_.batches;

        // 批之间自然停顿：不固定、长尾
        Sleep(static_cast<DWORD>(rnd::pareto_like_ms(180, 1.5)));
        return ok;
    }

    // 执行结构化任务批次（P1 主路径）：一个 Session 跑完整个 Batch
    std::vector<TaskResult> run(const Batch& b) {
        std::vector<TaskResult> results;
        if (b.empty()) return results;

        Session s;
        if (!s.Begin(pid_)) {
            RLOG(Warn, rlog::kEvSessionBegin, 1, pid_);
            return results;
        }

        const uint64_t t0 = ticks();
        results = execute(s, b);

        const uint64_t held = ticks() - t0;
        const uint64_t perMs = ticks_per_ms() ? ticks_per_ms() : 1;
        stats_.total_hold_us += held * 1000ull / perMs;
        const uint32_t ms = static_cast<uint32_t>(held / perMs);
        if (ms > stats_.max_life_ms) stats_.max_life_ms = ms;
        if (!s.alive()) {
            ++stats_.forced_closes;
            RLOG(Warn, rlog::kEvSessionTimeout, 1, ms);
        }
        s.Close();
        ++stats_.batches;
        RLOG(Trace, rlog::kEvSessionEnd, 2, stats_.batches, ms);

        Sleep(static_cast<DWORD>(rnd::pareto_like_ms(180, 1.5)));
        return results;
    }

    const Stats& stats() const noexcept { return stats_; }

    // 句柄审计：确认自身进程未持有目标进程句柄
    // 开销：一次全系统句柄表快照（本机几千条，约 1~3ms），只在批间调用
    struct Audit {
        bool executed = false;
        uint32_t target_handles = 0;
        uint32_t process_handles = 0;
        bool clean() const noexcept { return executed && target_handles == 0; }
    };

    Audit audit() const {
        const auto r = audit_handles(pid_);
        Audit a;
        a.executed = r.ok;
        a.target_handles = r.target_handles;
        a.process_handles = r.self_process_handles;
        if (a.executed && a.target_handles != 0) {
            RLOG(Error, rlog::kEvHandleAuditDirty, 2, a.target_handles, a.process_handles);
        }
        return a;
    }

    // 断言式版本：干净则继续，否则把该批标记为不可信
    bool assert_clean() const {
        const Audit a = audit();
        return a.clean();
    }

private:
    DWORD pid_;
    Stats stats_{};
};

}  // namespace os
