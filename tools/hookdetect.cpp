// hookdetect.cpp —— 检测游戏是否装了全局输入钩子
//
// 为什么重要：
//   rawspy 已证明 Raw Input 层看不到 SendInput 的注入标记。
//   llspy 已证明低级钩子层能看到（LLKHF_INJECTED=1）。
//
//   所以：游戏用 Raw Input => SendInput 完全干净，不需要驱动
//         游戏装低级钩子 => SendInput 会被标记
//
//   能否提前知道对方装没装钩子？这就是本程序要测的。
//
// 三条检测路径：
//   A. 共享桌面钩子链（user32!gSharedInfo 里的 aheList）
//      这是最直接的方法，但要解析未公开结构
//   B. 直接尝试装一个 WH_KEYBOARD_LL，看返回值与位置
//      如果装之前就有钩子，说明对方在监控
//   C. 观察 SendInput 后 GetLastError / 时序
//      钩子越多，SendInput 越慢
#include <windows.h>
#include <cstdio>

// ---- 路径 A：解析共享桌面钩子链 ----
// Windows 把全局钩子存在 win32kbase/user32 的共享堆里，
// 用户态可通过 user32!gSharedInfo 找到 aheList（句柄表）再筛钩子对象。
// 结构随版本变化，这里用"能力探测"而非硬解析：
// 通过 NtUserGetObjectInformation 之类没有公开 API，
// 所以实际可用的替代方案是路径 B + C。

// ---- 路径 B：尝试装钩子并观察 ----
struct HookProbe {
    bool installed = false;
    HHOOK handle = nullptr;
    DWORD lastError = 0;
    ULONGLONG latencyUs = 0;
};

static HHOOK g_kbd = nullptr;
static HOOKPROC g_proc = nullptr;
static volatile LONG g_kbdEvents = 0;

static LRESULT CALLBACK probeProc(int code, WPARAM wp, LPARAM lp) {
    if (code == HC_ACTION) InterlockedIncrement(&g_kbdEvents);
    return CallNextHookEx(g_kbd, code, wp, lp);
}

HookProbe try_install_kbd_hook() {
    HookProbe p;
    LARGE_INTEGER t0, t1, freq;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);

    SetLastError(0);
    p.handle = SetWindowsHookExW(WH_KEYBOARD_LL, probeProc, GetModuleHandleW(nullptr), 0);
    p.lastError = GetLastError();

    QueryPerformanceCounter(&t1);
    p.latencyUs = (ULONGLONG)((t1.QuadPart - t0.QuadPart) * 1000000 / freq.QuadPart);
    p.installed = p.handle != nullptr;
    return p;
}

// ---- 路径 C：测量 SendInput 延迟 ----
// 装了钩子的进程，每次 SendInput 都要等所有钩子回调完成（有超时）。
// 钩子越多、越慢，SendInput 耗时越长。
// 注意：这个测量需要自己在钩子回调里配合，这里只测"裸 SendInput"的基线。
ULONGLONG measure_sendinput_us(int samples) {
    LARGE_INTEGER freq, t0, t1;
    QueryPerformanceFrequency(&freq);

    INPUT in{};
    in.type = INPUT_KEYBOARD;
    in.ki.wVk = VK_F1;
    in.ki.dwFlags = KEYEVENTF_KEYUP;

    // 预热
    SendInput(1, &in, sizeof(INPUT));

    QueryPerformanceCounter(&t0);
    for (int i = 0; i < samples; ++i) SendInput(1, &in, sizeof(INPUT));
    QueryPerformanceCounter(&t1);

    return (ULONGLONG)((t1.QuadPart - t0.QuadPart) * 1000000 / freq.QuadPart / samples);
}

int main() {
    SetConsoleOutputCP(936);
    printf("=== hookdetect ===\n\n");

    // 测基线：无钩子时的 SendInput 延迟
    const ULONGLONG baseline = measure_sendinput_us(200);
    printf("[baseline] SendInput avg = %llu us (no hook installed by us)\n",
           (unsigned long long)baseline);

    // 装钩子后再测
    HookProbe p = try_install_kbd_hook();
    printf("[probe] SetWindowsHookEx(WH_KEYBOARD_LL) => %p (err=%lu, latency=%llu us)\n",
           (void*)p.handle, p.lastError, (unsigned long long)p.latencyUs);

    if (p.installed) {
        g_kbd = p.handle;

        // 泵消息让钩子生效
        MSG msg;
        for (int i = 0; i < 20; ++i) {
            while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
            Sleep(5);
        }

        const ULONGLONG withHook = measure_sendinput_us(200);
        printf("[with-hook] SendInput avg = %llu us (delta = %+lld us)\n",
               (unsigned long long)withHook,
               (long long)withHook - (long long)baseline);
        printf("[with-hook] kbd events seen by our hook = %ld\n", (long)g_kbdEvents);

        UnhookWindowsHookEx(p.handle);
    }

    printf("\n=== 判据 ===\n");
    printf("若游戏装了 WH_KEYBOARD_LL：\n");
    printf("  * SendInput 会被打上 LLKHF_INJECTED（llspy 已实测）\n");
    printf("  * 我们能通过 SendInput 延迟异常升高间接察觉（钩子回调要串行执行）\n");
    printf("若游戏只用 Raw Input：\n");
    printf("  * SendInput 完全干净（rawspy 已实测 ExtraInfo=0）\n");
    printf("  * 这就是绝大多数 MMO/FPS 的情况\n");

    return 0;
}
