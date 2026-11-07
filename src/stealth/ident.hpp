// stealth/ident.hpp —— 每次启动唯一的中性标识（进程/窗口/互斥体/管道）
// 原则：不伪装成 svchost.exe / explorer.exe 等系统进程（那是强伪装特征）
#pragma once

#include <windows.h>

#include <string>

#include "common/rnd.hpp"

namespace ident {

// 小写字母+数字，长度随机，形如 "k3v9xq2mz7" —— 无语义、无描述
inline std::wstring token(size_t minLen = 8, size_t maxLen = 14) {
    static const wchar_t kAlphabet[] = L"abcdefghijklmnopqrstuvwxyz0123456789";
    const size_t len = static_cast<size_t>(rnd::between(static_cast<int64_t>(minLen),
                                                       static_cast<int64_t>(maxLen)));
    std::wstring s;
    s.reserve(len);
    for (size_t i = 0; i < len; ++i) {
        s.push_back(kAlphabet[rnd::between(0, 35)]);
    }
    // 首位强制字母，避免生成看起来像版本号的串
    if (!s.empty() && s[0] >= L'0' && s[0] <= L'9') s[0] = L'q';
    return s;
}

// 窗口加固：不进任务栏、不抢焦点、不出现辅助工具常见样式组合
inline void harden_window(HWND h) noexcept {
    if (!h) return;
    const LONG_PTR ex = GetWindowLongPtrW(h, GWL_EXSTYLE);
    SetWindowLongPtrW(h, GWL_EXSTYLE,
                      ex | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE);
    SetWindowLongPtrW(h, GWLP_USERDATA, 0);
}

// 内存中构造一次性的单实例互斥体名（Global\ 前缀每次随机）
inline std::wstring mutex_name() {
    return L"Global\\" + token(12, 18);
}

// 命名管道名（服务端方向），后缀随机
inline std::wstring pipe_name() {
    return L"\\\\.\\pipe\\" + token(10, 16);
}

}  // namespace ident
