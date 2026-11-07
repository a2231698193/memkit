// os/scan.hpp —— 目标进程定位 + 模块基址
// 说明：MVP 走 Toolhelp32 快照（句柄级短暂、无目标进程句柄），
//      内存访问一律走 os::Session 的 Nt* 路径
#pragma once

#include <windows.h>
#include <tlhelp32.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "common/hash.hpp"
#include "common/obf.hpp"

namespace os {

inline std::wstring lower_copy(const wchar_t* s, size_t n) {
    std::wstring w(s, n);
    for (auto& c : w) {
        if (c >= L'A' && c <= L'Z') c = static_cast<wchar_t>(c - L'A' + L'a');
    }
    return w;
}

struct ProcEntry {
    DWORD pid = 0;
    DWORD ppid = 0;
    std::wstring name;  // 小写
};

// 快照对象：析构即关句柄，生命周期严格绑定作用域
class Snapshot {
public:
    explicit Snapshot(DWORD flags, DWORD pid = 0)
        : h_(CreateToolhelp32Snapshot(flags, pid)) {}
    ~Snapshot() {
        if (h_ != INVALID_HANDLE_VALUE) CloseHandle(h_);
    }
    Snapshot(const Snapshot&) = delete;
    Snapshot& operator=(const Snapshot&) = delete;

    bool ok() const noexcept { return h_ != INVALID_HANDLE_VALUE; }
    HANDLE get() const noexcept { return h_; }

private:
    HANDLE h_ = INVALID_HANDLE_VALUE;
};

inline std::vector<ProcEntry> enum_processes() {
    std::vector<ProcEntry> out;
    Snapshot snap(TH32CS_SNAPPROCESS);
    if (!snap.ok()) return out;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (!Process32FirstW(snap.get(), &pe)) return out;

    do {
        ProcEntry e;
        e.pid = pe.th32ProcessID;
        e.ppid = pe.th32ParentProcessID;
        e.name = lower_copy(pe.szExeFile, wcslen(pe.szExeFile));
        if (e.pid != 0) out.push_back(std::move(e));
    } while (Process32NextW(snap.get(), &pe));

    return out;
}

// 按小写进程名找全部 pid（支持多开）
inline std::vector<DWORD> find_pid(const std::wstring& exeLower) {
    std::vector<DWORD> pids;
    for (auto& e : enum_processes()) {
        if (e.name == exeLower) pids.push_back(e.pid);
    }
    return pids;
}

// 目标进程内模块基址；失败返回 0
inline uintptr_t module_base(DWORD pid, const std::wstring& modLower, size_t* size = nullptr) {
    Snapshot snap(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (!snap.ok()) return 0;

    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    if (!Module32FirstW(snap.get(), &me)) return 0;

    do {
        const std::wstring n = lower_copy(me.szModule, wcslen(me.szModule));
        if (n == modLower) {
            if (size) *size = me.modBaseSize;
            return reinterpret_cast<uintptr_t>(me.modBaseAddr);
        }
    } while (Module32NextW(snap.get(), &me));

    return 0;
}

}  // namespace os
