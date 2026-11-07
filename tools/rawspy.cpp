// rawspy.cpp —— 实测各输入通道在 Raw Input 层的可见特征
//
// 目的：回答一个只能靠实测的问题——
//   SendInput / PostMessage / InjectSyntheticPointerInput 产生的输入，
//   在游戏用的 Raw Input 通道上留下什么痕迹？
//
// 记录四项：
//   1. RAWKEYBOARD / RAWMOUSE 的原始字段
//   2. GetMessageExtraInfo()（低级钩子能看到的注入标记）
//   3. GetAsyncKeyState / GetKeyState（真实键状态）
//   4. WM_INPUT 的 wParam（RIM_INPUT vs RIM_INPUTSINK）
#include <windows.h>
#include <cstdio>
#include <vector>

static FILE* g_log = nullptr;

static void logf(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    if (g_log) vfprintf(g_log, fmt, ap);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
}

// 隐藏窗口，用 RIDEV_INPUTSINK 在后台也能收输入
static LRESULT CALLBACK wndproc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg != WM_INPUT) return DefWindowProcW(h, msg, wp, lp);

    UINT size = 0;
    GetRawInputData(reinterpret_cast<HRAWINPUT>(lp), RID_INPUT, nullptr, &size,
                    sizeof(RAWINPUTHEADER));
    if (size == 0 || size > 4096) return 0;

    BYTE buf[4096];
    if (GetRawInputData(reinterpret_cast<HRAWINPUT>(lp), RID_INPUT, buf, &size,
                        sizeof(RAWINPUTHEADER)) != size) {
        return 0;
    }

    const auto* ri = reinterpret_cast<const RAWINPUT*>(buf);
    const char* tag = (ri->header.dwType == RIM_TYPEKEYBOARD) ? "KBD"
                     : (ri->header.dwType == RIM_TYPEMOUSE)    ? "MOU"
                                                              : "???";
    const DWORD extra = static_cast<DWORD>(GetMessageExtraInfo());
    const bool lowLevelInjected = (extra & 0xFFFFFF00u) == 0xFF515700u;
    const bool injectedBit = (extra & 0x00000001u) != 0;

    if (ri->header.dwType == RIM_TYPEKEYBOARD) {
        const RAWKEYBOARD& k = ri->data.keyboard;
        logf("[%s] wParam=%s VKey=0x%02X Scan=0x%02X Flags=0x%04X Msg=%s "
             "ExtraInfo=0x%08lX LLInjected=%d InjectedBit=%d "
             "AsyncState=0x%04X\n",
             tag, wp == RIM_INPUT ? "RIM_INPUT" : "RIM_INPUTSINK",
             k.VKey, k.MakeCode, k.Flags, k.Message == WM_KEYDOWN ? "DOWN"
                                              : k.Message == WM_KEYUP ? "UP"
                                                                      : "?",
             extra, lowLevelInjected ? 1 : 0, injectedBit ? 1 : 0,
             GetAsyncKeyState(k.VKey) & 0xFFFF);
    } else {
        const RAWMOUSE& m = ri->data.mouse;
        logf("[%s] wParam=%s usFlags=0x%04X Buttons=0x%04X "
             "RawButtons=0x%08lX LastX=%ld LastY=%ld ExtraInfo=0x%08lX "
             "LLInjected=%d InjectedBit=%d\n",
             tag, wp == RIM_INPUT ? "RIM_INPUT" : "RIM_INPUTSINK",
             m.usFlags, m.ulButtons, m.ulRawButtons, m.lLastX, m.lLastY,
             extra, lowLevelInjected ? 1 : 0, injectedBit ? 1 : 0);
    }
    fflush(g_log);
    return 0;
}

static HWND make_hidden_window(HINSTANCE inst) {
    WNDCLASSW wc{};
    wc.lpfnWndProc = wndproc;
    wc.hInstance = inst;
    wc.lpszClassName = L"rawspy_wnd";
    RegisterClassW(&wc);
    return CreateWindowExW(0, L"rawspy_wnd", L"", WS_POPUP, 0, 0, 1, 1,
                           HWND_MESSAGE, nullptr, inst, nullptr);
}

static bool register_raw(HWND h) {
    RAWINPUTDEVICE rid[2]{};
    rid[0].usUsagePage = 0x01;  // Generic Desktop
    rid[0].usUsage = 0x06;      // Keyboard
    rid[0].dwFlags = RIDEV_INPUTSINK;
    rid[0].hwndTarget = h;
    rid[1].usUsagePage = 0x01;
    rid[1].usUsage = 0x02;      // Mouse
    rid[1].dwFlags = RIDEV_INPUTSINK;
    rid[1].hwndTarget = h;
    return RegisterRawInputDevices(rid, 2, sizeof(RAWINPUTDEVICE)) != FALSE;
}

static void pump(int ms) {
    const DWORD end = GetTickCount() + ms;
    MSG msg;
    while (GetTickCount() < end) {
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        Sleep(5);
    }
}

int main(int argc, char** argv) {
    g_log = fopen("rawspy.log", "w");
    SetConsoleOutputCP(936);

    HINSTANCE inst = GetModuleHandleW(nullptr);
    const HWND h = make_hidden_window(inst);
    if (!h) { logf("CreateWindow failed: %lu\n", GetLastError()); return 1; }
    if (!register_raw(h)) { logf("RegisterRawInputDevices failed: %lu\n", GetLastError()); return 1; }

    logf("=== rawspy ready ===\n");
    logf("Usage: rawspy sendinput|postmsg|synthetic|all\n\n");
    pump(200);

    const char* mode = argc > 1 ? argv[1] : "all";

    auto do_sendinput = [&](const char* label) {
        logf("\n--- SendInput: %s ---\n", label);
        INPUT in[2]{};
        in[0].type = INPUT_KEYBOARD;
        in[0].ki.wVk = 'A';
        in[0].ki.wScan = static_cast<WORD>(MapVirtualKeyW('A', MAPVK_VK_TO_VSC));
        in[1] = in[0];
        in[1].ki.dwFlags = KEYEVENTF_KEYUP;
        logf("(sending A down/up)\n");
        SendInput(1, &in[0], sizeof(INPUT));
        pump(120);
        SendInput(1, &in[1], sizeof(INPUT));
        pump(200);

        logf("\n--- SendInput: mouse move ---\n");
        INPUT mv{};
        mv.type = INPUT_MOUSE;
        mv.mi.dwFlags = MOUSEEVENTF_MOVE;
        mv.mi.dx = 10; mv.mi.dy = 5;
        SendInput(1, &mv, sizeof(INPUT));
        pump(200);
    };

    auto do_postmsg = [&](const char* label) {
        logf("\n--- PostMessage(WM_KEYDOWN/UP): %s ---\n", label);
        logf("(posting to own hwnd; Raw Input does NOT see posted messages)\n");
        PostMessageW(h, WM_KEYDOWN, 'B', 0x00300001);
        pump(120);
        PostMessageW(h, WM_KEYUP, 'B', 0xC0300001);
        pump(200);
    };

    auto do_synthetic = [&](const char* label) {
        logf("\n--- InjectSyntheticPointerInput: %s ---\n", label);
        using CreateFn = HSYNTHETICPOINTERDEVICE(WINAPI*)(POINTER_INPUT_TYPE, ULONG, POINTER_FEEDBACK_MODE);
        using InjectFn = BOOL(WINAPI*)(HSYNTHETICPOINTERDEVICE, const POINTER_TYPE_INFO*, UINT32);
        using DestroyFn = void(WINAPI*)(HSYNTHETICPOINTERDEVICE);

        HMODULE u32 = GetModuleHandleW(L"user32.dll");
        auto create = reinterpret_cast<CreateFn>(GetProcAddress(u32, "CreateSyntheticPointerDevice"));
        auto inject = reinterpret_cast<InjectFn>(GetProcAddress(u32, "InjectSyntheticPointerInput"));
        auto destroy = reinterpret_cast<DestroyFn>(GetProcAddress(u32, "DestroySyntheticPointerDevice"));

        if (!create || !inject) { logf("  API missing\n"); return; }

        // PT_MOUSE = 4，文档说保留；实测看返回值
        HSYNTHETICPOINTERDEVICE dev = create(PT_MOUSE, 1, POINTER_FEEDBACK_DEFAULT);
        logf("  CreateSyntheticPointerDevice(PT_MOUSE) => %p (err=%lu)\n", (void*)dev, GetLastError());
        if (!dev) {
            dev = create(PT_TOUCH, 1, POINTER_FEEDBACK_DEFAULT);
            logf("  CreateSyntheticPointerDevice(PT_TOUCH) => %p (err=%lu)\n", (void*)dev, GetLastError());
        }
        if (!dev) return;

        POINTER_TYPE_INFO info{};
        info.type = PT_TOUCH;
        info.touchInfo.pointerInfo.pointerType = PT_TOUCH;
        info.touchInfo.pointerInfo.pointerId = 1;
        info.touchInfo.pointerInfo.pointerFlags = POINTER_FLAG_DOWN | POINTER_FLAG_INRANGE | POINTER_FLAG_INCONTACT;
        info.touchInfo.pointerInfo.ptPixelLocation.x = 100;
        info.touchInfo.pointerInfo.ptPixelLocation.y = 100;
        info.touchInfo.touchFlags = TOUCH_FLAG_NONE;
        info.touchInfo.touchMask = TOUCH_MASK_CONTACTAREA | TOUCH_MASK_ORIENTATION | TOUCH_MASK_PRESSURE;
        info.touchInfo.rcContact.left = 98; info.touchInfo.rcContact.top = 98;
        info.touchInfo.rcContact.right = 102; info.touchInfo.rcContact.bottom = 102;
        info.touchInfo.orientation = 90;
        info.touchInfo.pressure = 32000;

        const BOOL ok = inject(dev, &info, 1);
        logf("  InjectSyntheticPointerInput(TOUCH down) => %d (err=%lu)\n", ok ? 1 : 0, GetLastError());
        pump(200);

        info.touchInfo.pointerInfo.pointerFlags = POINTER_FLAG_UP;
        const BOOL ok2 = inject(dev, &info, 1);
        logf("  InjectSyntheticPointerInput(TOUCH up) => %d (err=%lu)\n", ok2 ? 1 : 0, GetLastError());
        pump(200);

        destroy(dev);
    };

    if (strcmp(mode, "sendinput") == 0
 || strcmp(mode, "all") == 0) do_sendinput(mode);
    if (strcmp(mode, "postmsg") == 0 || strcmp(mode, "all") == 0) do_postmsg(mode);
    if (strcmp(mode, "synthetic") == 0 || strcmp(mode, "all") == 0) do_synthetic(mode);

    logf("\n=== done ===\n");
    if (g_log) fclose(g_log);
    return 0;
}
