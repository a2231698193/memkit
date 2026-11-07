// stealth/manifest.hpp —— 运行时清单与自检汇总
// 目的：把所有"暴露面"集中在一处声明，便于每次提交回归
#pragma once

#include <windows.h>

#include <cstdint>
#include <string>

#include "common/obf.hpp"
#include "stealth/antidebug.hpp"
#include "stealth/ident.hpp"

namespace stealth {

// 当前进程的暴露面快照（不进日志文件，只在内存里做断言）
struct Surface {
    bool debugger_present = false;
    bool hostile_module = false;
    bool hw_breakpoint = false;
    bool long_lived_handle = false;  // 由 os::Scheduler 反馈
    std::wstring instance_token;     // 每次启动唯一
};

inline Surface probe() noexcept {
    Surface s;
    s.debugger_present = adbg::peb_flag() || adbg::debug_object();
    s.hostile_module = adbg::hostile_module();
    s.hw_breakpoint = adbg::hw_breakpoint();
    s.instance_token = ident::token(12, 18);
    return s;
}

// 是否允许继续运行（任何失败项都直接退出，不提示）
inline bool gate() noexcept {
    const Surface s = probe();
    return !s.debugger_present && !s.hostile_module && !s.hw_breakpoint;
}

// 生成运行期标识：进程名后缀、管道名、互斥体名都从这里派生
inline std::wstring instance_id() {
    static const std::wstring id = ident::token(10, 16);
    return id;
}

}  // namespace stealth
