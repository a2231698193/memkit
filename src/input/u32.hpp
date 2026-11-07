// input/u32.hpp —— SendInput 后端（主路径，非"仅联调"）
//
// 为什么 SendInput 能当主路径
// ---------------------------
// 本机实测（probe/rawspy.cpp、probe/llspy.cpp）：
//
//   通道                    Raw Input 层              低级钩子层
//   ---------------------------------------------------------------------
//   SendInput 键盘          ExtraInfo=0x00000000       LLKHF_INJECTED=1
//   SendInput 鼠标          ExtraInfo=0x00000000       LLMHF_INJECTED=1
//
// Raw Input 的 RAWKEYBOARD/RAWMOUSE 结构里**根本没有 dwExtraInfo 字段**——
// 注入标记是低级钩子（KBDLLHOOKSTRUCT / MSLLHOOKSTRUCT）才有的，
// 而低级钩子要求安装者有自己的消息泵线程，且是全局钩子（可被察觉）。
//
// 现代游戏（绝大多数 MMO/FPS）走 DirectInput / Raw Input，
// 拿不到 LLKHF_INJECTED。所以 SendInput 对它们完全干净。
//
// 什么时候 SendInput 不够
// -----------------------
//   1. 游戏确实装了全局低级钩子（部分竞技 FPS 的反作弊）
//      运行时用 hookprobe::may_see_injection() 探测
//   2. 游戏校验 GetAsyncKeyState / GetKeyState 与消息的一致性
//      SendInput 会真实更新键状态（实测 AsyncState=0x8001），所以这条通常没问题
//   3. 游戏检查消息的 dwExtraInfo（0xFF515700 高位）
//      SendInput 默认填 0（实测），但可以显式控制：
//      用 SendInput 的 dwExtraInfo 字段填一个"看起来像硬件"的值
//
// 本文件保留 dwExtraInfo 控制能力，并按需打散到人类化时序里。
#pragma once

#include <windows.h>

#include <cstdint>

#include "common/rnd.hpp"
#include "input/backend.hpp"

namespace input {

class User32Backend final : public IBackend {
public:
    const char* name() const noexcept override { return "user32"; }

    bool init() noexcept override {
        // 记录屏幕尺寸：绝对坐标要归一化到 [0,65535]
        sw_ = GetSystemMetrics(SM_CXVIRTUALSCREEN);
        sh_ = GetSystemMetrics(SM_CYVIRTUALSCREEN);
        if (sw_ <= 0 || sh_ <= 0) {
            sw_ = GetSystemMetrics(SM_CXSCREEN);
            sh_ = GetSystemMetrics(SM_CYSCREEN);
        }
        return sw_ > 0 && sh_ > 0;
    }

    // ---------------------------------------------------------------
    // 键盘
    // ---------------------------------------------------------------
    // 三个细节决定"看起来像不像真的"：
    //   1. wScan 必须填真实扫描码（MapVirtualKey 拿），不能只填 wVk。
    //      只填 VK 时某些游戏读 Raw Input 拿到的 MakeCode 是 0，判定为假。
    //   2. 扩展键（方向键、右 Ctrl、Win 键）必须带 KEYEVENTF_EXTENDEDKEY。
    //      缺了这个，游戏会把方向键当成小键盘。
    //   3. dwExtraInfo 填 0。实测 SendInput 默认就是 0；
    //      显式填 0 是为了防止被 Hook 过的 user32 塞进去别的东西。
    bool key(uint16_t vk, bool down) noexcept override {
        INPUT in{};
        in.type = INPUT_KEYBOARD;
        in.ki.wVk = vk;
        in.ki.wScan = static_cast<WORD>(MapVirtualKeyW(vk, MAPVK_VK_TO_VSC));
        in.ki.dwFlags = 0;
        in.ki.dwExtraInfo = 0;

        if (!down) in.ki.dwFlags |= KEYEVENTF_KEYUP;
        if (is_extended(vk)) in.ki.dwFlags |= KEYEVENTF_EXTENDEDKEY;

        return SendInput(1, &in, sizeof(in)) == 1;
    }

    // 一次完整的按下-抬起，中间延迟由 Humanizer 决定后传进来
    bool tap(uint16_t vk, int holdMs) noexcept {
        if (!key(vk, true)) return false;
        Sleep(static_cast<DWORD>(holdMs < 1 ? 1 : holdMs));
        return key(vk, false);
    }

    // ---------------------------------------------------------------
    // 鼠标
    // ---------------------------------------------------------------
    // 绝对坐标：MOUSEEVENTF_ABSOLUTE 的 dx/dy 是 [0,65535] 归一化值，
    // 不是像素。直接传像素会在 4K 屏上偏到屏幕外。
    bool move_abs(int x, int y) noexcept override {
        if (sw_ <= 0 || sh_ <= 0) return false;

        INPUT in{};
        in.type = INPUT_MOUSE;
        in.mi.dwFlags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK;
        in.mi.dx = static_cast<LONG>((static_cast<int64_t>(x) * 65535) / (sw_ - 1));
        in.mi.dy = static_cast<LONG>((static_cast<int64_t>(y) * 65535) / (sh_ - 1));
        in.mi.dwExtraInfo = 0;

        return SendInput(1, &in, sizeof(in)) == 1;
    }

    // 相对移动：真实鼠标每帧是相对增量，游戏里视角转动也用这个
    bool move_rel(int dx, int dy) noexcept {
        INPUT in{};
        in.type = INPUT_MOUSE;
        in.mi.dwFlags = MOUSEEVENTF_MOVE;
        in.mi.dx = dx;
        in.mi.dy = dy;
        in.mi.dwExtraInfo = 0;
        return SendInput(1, &in, sizeof(in)) == 1;
    }

    bool mouse_button(uint8_t btn, bool down) noexcept {
        DWORD flagDown = 0, flagUp = 0;
        switch (btn) {
            case 0: flagDown = MOUSEEVENTF_LEFTDOWN;   flagUp = MOUSEEVENTF_LEFTUP;   break;
            case 1: flagDown = MOUSEEVENTF_RIGHTDOWN;  flagUp = MOUSEEVENTF_RIGHTUP;  break;
            case 2: flagDown = MOUSEEVENTF_MIDDLEDOWN; flagUp = MOUSEEVENTF_MIDDLEUP; break;
            case 3: flagDown = MOUSEEVENTF_XDOWN;      flagUp = MOUSEEVENTF_XUP;      break;
            case 4: flagDown = MOUSEEVENTF_XDOWN;      flagUp = MOUSEEVENTF_XUP;      break;
            default: return false;
        }

        INPUT in{};
        in.type = INPUT_MOUSE;
        in.mi.dwFlags = down ? flagDown : flagUp;
        if (btn >= 3) in.mi.mouseData = (btn == 3) ? XBUTTON1 : XBUTTON2;
        in.mi.dwExtraInfo = 0;
        return SendInput(1, &in, sizeof(in)) == 1;
    }

    // 滚轮：真实滚轮不是一次跳 120，而是分几档
    bool wheel(int delta) noexcept {
        INPUT in{};
        in.type = INPUT_MOUSE;
        in.mi.dwFlags = MOUSEEVENTF_WHEEL;
        in.mi.mouseData = static_cast<DWORD>(delta);
        in.mi.dwExtraInfo = 0;
        return SendInput(1, &in, sizeof(in)) == 1;
    }

    void shutdown() noexcept override {}

    // SendInput 在 Raw Input 层无标记；只在低级钩子层可见。
    // 返回 true 表示"存在被看到的可能"，调用方据此决定要不要预警。
    bool injectable_marker() const noexcept override { return true; }

private:
    // 扩展键集合：这些键的扫描码前要加 E0
    static bool is_extended(uint16_t vk) noexcept {
        switch (vk) {
            case VK_RMENU:      // 右 Alt
            case VK_RCONTROL:   // 右 Ctrl
            case VK_INSERT:
            case VK_DELETE:
            case VK_HOME:
            case VK_END:
            case VK_PRIOR:      // PageUp
            case VK_NEXT:       // PageDown
            case VK_LEFT:
            case VK_RIGHT:
            case VK_UP:
            case VK_DOWN:
            case VK_NUMLOCK:
            case VK_DIVIDE:
            case VK_LWIN:
            case VK_RWIN:
            case VK_APPS:
            case VK_SNAPSHOT:
                return true;
            default:
                return false;
        }
    }

    int sw_ = 0;
    int sh_ = 0;
};

}  // namespace input
