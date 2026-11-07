// input/backend.hpp —— 输入后端抽象 + 人类化调度（不绑定具体实现）
#pragma once

#include <windows.h>

#include <algorithm>
#include <cstdint>
#include <vector>

#include "common/rnd.hpp"

namespace input {

// 所有输入后端实现此接口。MVP 只有 User32（可检测）与 Driver（占位）。
class IBackend {
public:
    virtual ~IBackend() = default;

    virtual const char* name() const noexcept = 0;
    virtual bool init() noexcept = 0;
    virtual bool key(uint16_t vk, bool down) noexcept = 0;
    virtual bool move_abs(int x, int y) noexcept = 0;
    virtual void shutdown() noexcept = 0;

    // 该后端是否会在消息链上留下"注入"标记（LLMHF_INJECTED / ExtraInfo 0xFF5157xx）
    virtual bool injectable_marker() const noexcept = 0;
};

// 人类化调度：延迟分布、贝塞尔轨迹、疲劳曲线、微停顿
class Humanizer {
public:
    // 对数正态延迟，避免固定 interval 被时序统计识别
    int tap_delay(int p50 = 90) noexcept { return rnd::lognorm_ms(p50 + fatigue_ms(), 0.42); }

    int hold_ms(int p50 = 120) noexcept { return rnd::lognorm_ms(p50 + fatigue_ms(), 0.35); }

    // 批处理会话之间的停顿：幂律长尾，模仿看屏幕的思考节奏
    int idle_gap(int minMs = 400) noexcept { return rnd::pareto_like_ms(minMs); }

    // 三次贝塞尔 + 抖动：轨迹不做等比直线，端点附近密度更高
    void curve(POINT a, POINT b, std::vector<POINT>& out) {
        const int steps = static_cast<int>(rnd::between(14, 30));
        const int wob = 36;
        POINT c1{a.x + (b.x - a.x) / 3 + jitter(wob), a.y + (b.y - a.y) / 3 + jitter(wob)};
        POINT c2{a.x + 2 * (b.x - a.x) / 3 + jitter(wob),
                 a.y + 2 * (b.y - a.y) / 3 + jitter(wob)};

        out.clear();
        out.reserve(static_cast<size_t>(steps) + 1);
        for (int i = 0; i <= steps; ++i) {
            const double t = static_cast<double>(i) / steps;
            const double u = 1.0 - t;
            const double x = u * u * u * a.x + 3 * u * u * t * c1.x + 3 * u * t * t * c2.x +
                             t * t * t * b.x;
            const double y = u * u * u * a.y + 3 * u * u * t * c1.y + 3 * u * t * t * c2.y +
                             t * t * t * b.y;
            // 首点必须精确命中起点（当前光标位置），后续点加 1px 抖动
            const int jx = (i == 0) ? 0 : jitter(1);
            const int jy = (i == 0) ? 0 : jitter(1);
            out.push_back(POINT{static_cast<LONG>(x) + jx, static_cast<LONG>(y) + jy});
        }
    }

    // 步间延迟：中段快、两端慢（人类加速-减速特征）
    int step_delay(size_t i, size_t total) noexcept {
        const double t = total ? static_cast<double>(i) / total : 0.0;
        const double bell = 0.4 + 1.6 * (2.0 * t - 1.0) * (2.0 * t - 1.0);
        return std::max(1, static_cast<int>(rnd::lognorm_ms(static_cast<int>(4 + 10 * bell), 0.3)));
    }

    int jitter(int amp) noexcept {
        if (amp <= 0) return 0;
        return static_cast<int>(rnd::between(-amp, amp));
    }

    // 疲劳：连续动作越多越慢，空转后恢复
    void on_action() noexcept {
        ++streak_;
        fatigue_ = std::min(1.0, fatigue_ + 0.0025);
    }
    void on_idle() noexcept {
        streak_ = 0;
        fatigue_ = std::max(0.0, fatigue_ - 0.06);
    }
    double fatigue() const noexcept { return fatigue_; }
    int streak() const noexcept { return streak_; }

    void sleep_tap(int p50 = 90) noexcept { Sleep(static_cast<DWORD>(tap_delay(p50))); }
    void sleep_idle(int minMs = 400) noexcept { Sleep(static_cast<DWORD>(idle_gap(minMs))); }

private:
    int fatigue_ms() const noexcept { return static_cast<int>(fatigue_ * 90.0); }

    int streak_ = 0;
    double fatigue_ = 0.0;
};

}  // namespace input
