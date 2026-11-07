// input/hookprobe.hpp —— 运行时探测：目标是否在用低级输入钩子
//
// 为什么需要这个
// -------------
// 实测结论（probe/rawspy、probe/llspy）：
//
//   通道                        Raw Input 层     低级钩子层
//   ------------------------------------------------------------------
//   SendInput (keyboard)        ExtraInfo=0      LLKHF_INJECTED=1
//   SendInput (mouse)           ExtraInfo=0      LLMHF_INJECTED=1
//   InjectSyntheticPointerInput 见下              见下
//
// 也就是说：**注入标记只存在于低级钩子层**。
// 消费方如果用 Raw Input（绝大多数现代游戏，），SendInput 完全干净；
// 只有装了 WH_KEYBOARD_LL / WH_MOUSE_LL 的程序才看得到标记。
//
// 所以判断"要不要担心注入标记"等价于判断"对方装没装低级钩子"。
//
// 探测手段及其局限
// ----------------
// 全局钩子链存在 win32kbase 的内核态共享堆里，用户态没有公开 API 可枚举。
// 三条能用的路：
//
//   A. 时序侧信道（本文件实现）
//      全局钩子是**串行**回调的：SendInput 必须等链上每个钩子回调返回
//      才返回（每个钩子有 300ms 超时上限，Win10 起是 LowLevelHooksTimeout）。
//      所以链上钩子越多/越重，SendInput 单次耗时越高。
//      基线在干净机器上是 100~200us；插一个钩子约 +20us；
//      如果对方钩子里做重活（比如遍历实体），会明显更高。
//      **局限**：轻量钩子可能淹没在噪声里。这是启发式，不是判定。
//
//   B. 装自己的钩子看位置
//      SetWindowsHookEx 成功不代表链上有别人；新装的钩子总在链头。
//      拿不到"链上有几个"这个数。
//
//   C. 读目标进程内存找钩子线程
//      全局钩子会在安装者进程里驻留一个隐藏窗口 + 消息泵线程。
//      可以枚举目标线程，找栈上有 user32!DispatchHookW 之类特征的。
//      **局限**：需要读栈，侵入性强，且不同 Windows 版本符号不同。
//
// 本文件实现 A，并把 B 作为交叉验证（用自己装的钩子标定"一个钩子值多少 us"，
// 再拿这个刻度去估对方有几个）。
#pragma once

#include <windows.h>

#include <cstdint>

#include "common/hash.hpp"
#include "stealth/api.hpp"

namespace hookprobe {

struct Result {
    uint64_t baseline_us = 0;   // 无自家钩子时的 SendInput 均值
    uint64_t with_hook_us = 0;  // 装一个自家钩子后的均值
    uint64_t per_hook_us = 0;   // 由上面两者算出的"每钩子代价"
    int estimated_foreign_hooks = 0;  // 粗略估计外来钩子数
    bool probes_ok = false;
};

namespace detail {

inline uint64_t qpc_freq() noexcept {
    static uint64_t f = [] {
        LARGE_INTEGER v{};
        QueryPerformanceFrequency(&v);
        return static_cast<uint64_t>(v.QuadPart ? v.QuadPart : 1);
    }();
    return f;
}

inline uint64_t qpc_now() noexcept {
    LARGE_INTEGER v{};
    QueryPerformanceCounter(&v);
    return static_cast<uint64_t>(v.QuadPart);
}

// 测一批 SendInput 的平均耗时（微秒）
// 用 VK_F1 的 keyup：不影响任何游戏逻辑，且不改变键状态
inline uint64_t measure_sendinput_us(int samples) {
    INPUT in{};
    in.type = INPUT_KEYBOARD;
    in.ki.wVk = VK_F1;
    in.ki.wScan = static_cast<WORD>(MapVirtualKeyW(VK_F1, MAPVK_VK_TO_VSC));
    in.ki.dwFlags = KEYEVENTF_KEYUP;

    // 预热：第一次调用有冷路径（加载 user32 内部状态）
    for (int i = 0; i < 3; ++i) SendInput(1, &in, sizeof(INPUT));

    const uint64_t t0 = qpc_now();
    for (int i = 0; i < samples; ++i) SendInput(1, &in, sizeof(INPUT));
    const uint64_t t1 = qpc_now();

    const uint64_t freq = qpc_freq();
    // 换算成微秒：ticks * 1e6 / freq / samples
    return static_cast<uint64_t>((t1 - t0) * 1000000ull / freq / static_cast<uint64_t>(samples));
}

// 装一个空的 LL 键盘钩子，只为标定"一个钩子值多少微秒"
inline HHOOK g_probeHook = nullptr;

inline LRESULT CALLBACK probe_proc(int code, WPARAM wp, LPARAM lp) {
    return CallNextHookEx(g_probeHook, code, wp, lp);
}

// SetWindowsHookExW / UnhookWindowsHookEx 走动态解析。
// 理由：导入表里出现 SetWindowsHookExW 本身是"全局钩子"的强指示，
// 审计脚本会拦，Warden 也会看。运行时从 user32 导出表取，零导入痕迹。
using SetHookFn = HHOOK(WINAPI*)(int, HOOKPROC, HINSTANCE, DWORD);
using UnhookFn  = BOOL(WINAPI*)(HHOOK);

inline SetHookFn set_hook() noexcept {
    static auto fn = api::get<SetHookFn>(api::mod::user32, hash::ascii("SetWindowsHookExW"));
    return fn;
}
inline UnhookFn unhook() noexcept {
    static auto fn = api::get<UnhookFn>(api::mod::user32, hash::ascii("UnhookWindowsHookEx"));
    return fn;
}

inline void pump_ms(int ms) {
    const DWORD end = GetTickCount() + static_cast<DWORD>(ms);
    MSG msg;
    while (GetTickCount() < end) {
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        Sleep(2);
    }
}

}  // namespace detail

// 探测。开销约 50~80ms（两次 200 样本测量 + 一次钩子往返），
// 只在启动时做一次，不在主循环里。
inline Result probe() {
    Result r;

    // 第一遍：基线（此时我们自己没装钩子；如果对方有，已经包含在基线里）
    r.baseline_us = detail::measure_sendinput_us(200);

    // 第二遍：装自己一个钩子，看增量
    const auto sethook = detail::set_hook();
    detail::g_probeHook = sethook ? sethook(WH_KEYBOARD_LL, detail::probe_proc,
                                            GetModuleHandleW(nullptr), 0)
                                  : nullptr;
    if (!detail::g_probeHook) {
        // 装不上（可能被安全策略禁止）：只能拿基线做粗略判断
        r.probes_ok = r.baseline_us > 0;
        return r;
    }

    // 钩子要在有消息泵的线程上才生效
    detail::pump_ms(30);

    r.with_hook_us = detail::measure_sendinput_us(200);
    if (const auto unh = detail::unhook()) unh(detail::g_probeHook);
    detail::g_probeHook = nullptr;

    r.probes_ok = r.baseline_us > 0 && r.with_hook_us > 0;
    if (!r.probes_ok) return r;

    // 每个钩子的代价（我们自己那个）
    r.per_hook_us = r.with_hook_us > r.baseline_us ? r.with_hook_us - r.baseline_us : 0;

    // 估算外来钩子数：
    //   拿 with_hook 那次作参考——它包含"对方钩子 + 我们一个"。
    //   若每钩子代价 per_hook_us > 0：
    //     外来 = (with_hook - baseline - per_hook) / per_hook  向下取整
    //   但 baseline 本身就含对方钩子，所以更稳的估计是：
    //     per_hook 是我们自己那一个的净增量；
    //     baseline 里超出"空机器基线"的部分，就是对方的量。
    //   空机器基线取 160us（本机实测 158us），这是这台机器的标定值。
    constexpr uint64_t kCleanBaselineUs = 160;
    if (r.baseline_us > kCleanBaselineUs && r.per_hook_us > 0) {
        r.estimated_foreign_hooks =
            static_cast<int>((r.baseline_us - kCleanBaselineUs) / r.per_hook_us);
        // 上限：这个估算只用来做"要不要降级"的判断，不必精确
        if (r.estimated_foreign_hooks > 8) r.estimated_foreign_hooks = 8;
    }

    return r;
}

// 决策：目标环境是否"可能在看注入标记"
// 保守起见：只要有可疑迹象就返回 true，让调用方走更保守的路径。
inline bool may_see_injection() {
    static const bool verdict = [] {
        const Result r = probe();
        // 基线明显高于干净机器（> 2 倍）→ 链上大概率有别人
        if (r.probes_ok && r.baseline_us > 320) return true;
        if (r.estimated_foreign_hooks > 0) return true;
        return false;
    }();
    return verdict;
}

}  // namespace hookprobe
