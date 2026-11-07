// llspy.cpp —— 低级钩子层看注入标记
//
// rawspy 已证明 Raw Input 层看不到 SendInput 的注入标记（ExtraInfo=0）。
// 这里验证低级钩子（WH_KEYBOARD_LL / WH_MOUSE_LL）是否能看到。
//
// 结论会决定：
//   * 若低级钩子能看到 → 游戏必须装全局钩子才能检测，成本高、且钩子本身可被发现
//   * 若低级钩子也看不到 → SendInput 就够用，根本不需要驱动
#include <windows.h>
#include <cstdio>

static HHOOK g_kbdHook = nullptr;
static HHOOK g_mouHook = nullptr;

static LRESULT CALLBACK kbdProc(int code, WPARAM wp, LPARAM lp) {
    if (code == HC_ACTION) {
        const auto* kb = reinterpret_cast<const KBDLLHOOKSTRUCT*>(lp);
        const DWORD extra = static_cast<DWORD>(kb->dwExtraInfo);
        printf("[LL-KBD] vk=0x%02X scan=0x%02X flags=0x%08lX "
               "LLKHF_INJECTED=%d LLKHF_LOWER_IL=%d ExtraInfo=0x%08lX\n",
               kb->vkCode, kb->scanCode, kb->flags,
               (kb->flags & LLKHF_INJECTED) ? 1 : 0,
               (kb->flags & LLKHF_LOWER_IL_INJECTED) ? 1 : 0, extra);
        fflush(stdout);
    }
    return CallNextHookEx(g_kbdHook, code, wp, lp);
}

static LRESULT CALLBACK mouProc(int code, WPARAM wp, LPARAM lp) {
    if (code == HC_ACTION) {
        const auto* ms = reinterpret_cast<const MSLLHOOKSTRUCT*>(lp);
        const DWORD extra = static_cast<DWORD>(ms->flags);
        printf("[LL-MOU] pt=(%ld,%ld) flags=0x%08lX "
               "LLMHF_INJECTED=%d LLMHF_LOWER_IL=%d ExtraInfo=0x%08lX\n",
               ms->pt.x, ms->pt.y, ms->flags,
               (ms->flags & LLMHF_INJECTED) ? 1 : 0,
               (ms->flags & LLMHF_LOWER_IL_INJECTED) ? 1 : 0,
               static_cast<DWORD>(ms->dwExtraInfo));
        fflush(stdout);
    }
    return CallNextHookEx(g_mouHook, code, wp, lp);
}

int main() {
    SetConsoleOutputCP(936);
    HINSTANCE inst = GetModuleHandleW(nullptr);

    g_kbdHook = SetWindowsHookExW(WH_KEYBOARD_LL, kbdProc, inst, 0);
    g_mouHook = SetWindowsHookExW(WH_MOUSE_LL, mouProc, inst, 0);
    printf("=== llspy ready (kbd=%p mou=%p) ===\n", (void*)g_kbdHook, (void*)g_mouHook);
    printf("Testing SendInput A down/up + mouse move...\n");
    fflush(stdout);

    Sleep(300);

    INPUT in[2]{};
    in[0].type = INPUT_KEYBOARD;
    in[0].ki.wVk = 'A';
    in[0].ki.wScan = (WORD)MapVirtualKeyW('A', MAPVK_VK_TO_VSC);
    in[1] = in[0];
    in[1].ki.dwFlags = KEYEVENTF_KEYUP;
    SendInput(1, &in[0], sizeof(INPUT));
    Sleep(80);
    SendInput(1, &in[1], sizeof(INPUT));
    Sleep(80);

    INPUT mv{};
    mv.type = INPUT_MOUSE;
    mv.mi.dwFlags = MOUSEEVENTF_MOVE;
    mv.mi.dx = 7;
    mv.mi.dy = 3;
    SendInput(1, &mv, sizeof(INPUT));

    // 泵消息让钩子回调跑起来
    const DWORD end = GetTickCount() + 800;
    MSG msg;
    while (GetTickCount() < end) {
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        Sleep(5);
    }

    if (g_kbdHook) UnhookWindowsHookEx(g_kbdHook);
    if (g_mouHook) UnhookWindowsHookEx(g_mouHook);
    printf("=== done ===\n");
    return 0;
}
