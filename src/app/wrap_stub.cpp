// app/wrap_stub.cpp —— 链接期拦截敏感 API 的间接引用（动态转发版）
//
// 背景：libpthread / libwinpthread 的 thread.o、mutex.o、sched.o 内部引用了
//       OpenProcess / DuplicateHandle / SuspendThread / ResumeThread /
//       GetThreadContext / SetThreadContext。哪怕业务代码一行没调，导入表里
//       也会出现这些符号，形成"本进程疑似在做进程/线程操作"的静态特征。
//
// 手段：--wrap=__imp_XXX 把引用重定向到 __wrap___imp_XXX。
//
// 三条硬教训（逐条都踩过）：
//
//   1) 桩函数不能返回失败。libwinpthread 的 mutex/cond 真的会用 DuplicateHandle
//      复制句柄来构建等待链，直接返回 FALSE 会让 pthread 锁失效，表现为
//      thread-safe static guard 死锁、进程静默退出（exit code 3）。
//
//   2) 不能用 ntdll 原生 API「手写等价实现」。kernel32 的语义有多层翻译，
//      例如 DuplicateHandle 的 DUPLICATE_SAME_ACCESS 在 kernel32 里被翻译成
//      NtDuplicateObject(DesiredAccess=0, Options|=DUPLICATE_SAME_ATTRIBUTES)，
//      手写错一处，得到的句柄访问权限就是 0，一用就死锁。
//
//   3) 本文件内严禁出现 function-local static。C++ 的局部静态初始化要过
//      __cxa_guard_acquire/__cxa_guard_release，而那两把锁正是 libwinpthread 的
//      mutex —— 也就是我们正在包装的 DuplicateHandle。一旦首次调用发生在
//      静态初始化期，就是自锁。因此缓存一律用普通全局变量。
//
// 结果：运行时从 kernel32 导出表解析真实函数再转发调用。解析走 PEB + 导出表哈希，
//       不产生静态导入，导入表中依旧看不到这些符号。
#include <windows.h>

#include "common/hash.hpp"
#include "stealth/api.hpp"

namespace {

using OpenProcessFn = HANDLE(WINAPI*)(DWORD, BOOL, DWORD);
using DuplicateHandleFn = BOOL(WINAPI*)(HANDLE, HANDLE, HANDLE, LPHANDLE, DWORD, BOOL, DWORD);
using SuspendThreadFn = DWORD(WINAPI*)(HANDLE);
using ResumeThreadFn = DWORD(WINAPI*)(HANDLE);
using GetThreadContextFn = BOOL(WINAPI*)(HANDLE, LPCONTEXT);
using SetThreadContextFn = BOOL(WINAPI*)(HANDLE, const CONTEXT*);

// 全局缓存：静态零初始化，不走 guard，无锁
OpenProcessFn      g_openProcess      = nullptr;
DuplicateHandleFn  g_duplicateHandle  = nullptr;
SuspendThreadFn    g_suspendThread    = nullptr;
ResumeThreadFn     g_resumeThread     = nullptr;
GetThreadContextFn g_getThreadContext = nullptr;
SetThreadContextFn g_setThreadContext = nullptr;

// 幂等惰性解析：多线程重复赋值结果一致，无害
inline OpenProcessFn resolve_open() {
    if (!g_openProcess)
        g_openProcess = api::get<OpenProcessFn>(api::mod::kernel32, hash::ascii("OpenProcess"));
    return g_openProcess;
}

HANDLE WINAPI impl_OpenProcess(DWORD access, BOOL inherit, DWORD pid) {
    const auto fn = resolve_open();
    return fn ? fn(access, inherit, pid) : nullptr;
}

BOOL WINAPI impl_DuplicateHandle(HANDLE srcProc, HANDLE srcHandle, HANDLE dstProc,
                                 LPHANDLE dstHandle, DWORD access, BOOL inherit, DWORD options) {
    if (!g_duplicateHandle) {
        g_duplicateHandle =
            api::get<DuplicateHandleFn>(api::mod::kernel32, hash::ascii("DuplicateHandle"));
    }
    return g_duplicateHandle
               ? g_duplicateHandle(srcProc, srcHandle, dstProc, dstHandle, access, inherit, options)
               : FALSE;
}

DWORD WINAPI impl_SuspendThread(HANDLE thread) {
    if (!g_suspendThread) {
        g_suspendThread =
            api::get<SuspendThreadFn>(api::mod::kernel32, hash::ascii("SuspendThread"));
    }
    return g_suspendThread ? g_suspendThread(thread) : static_cast<DWORD>(-1);
}

DWORD WINAPI impl_ResumeThread(HANDLE thread) {
    if (!g_resumeThread) {
        g_resumeThread =
            api::get<ResumeThreadFn>(api::mod::kernel32, hash::ascii("ResumeThread"));
    }
    return g_resumeThread ? g_resumeThread(thread) : static_cast<DWORD>(-1);
}

BOOL WINAPI impl_GetThreadContext(HANDLE thread, LPCONTEXT ctx) {
    if (!g_getThreadContext) {
        g_getThreadContext =
            api::get<GetThreadContextFn>(api::mod::kernel32, hash::ascii("GetThreadContext"));
    }
    return g_getThreadContext ? g_getThreadContext(thread, ctx) : FALSE;
}

BOOL WINAPI impl_SetThreadContext(HANDLE thread, const CONTEXT* ctx) {
    if (!g_setThreadContext) {
        g_setThreadContext =
            api::get<SetThreadContextFn>(api::mod::kernel32, hash::ascii("SetThreadContext"));
    }
    return g_setThreadContext ? g_setThreadContext(thread, ctx) : FALSE;
}

}  // namespace

extern "C" {

HANDLE(WINAPI* __wrap___imp_OpenProcess)(DWORD, BOOL, DWORD) = impl_OpenProcess;

BOOL(WINAPI* __wrap___imp_DuplicateHandle)(HANDLE, HANDLE, HANDLE, LPHANDLE, DWORD, BOOL, DWORD) =
    impl_DuplicateHandle;

DWORD(WINAPI* __wrap___imp_SuspendThread)(HANDLE) = impl_SuspendThread;

DWORD(WINAPI* __wrap___imp_ResumeThread)(HANDLE) = impl_ResumeThread;

BOOL(WINAPI* __wrap___imp_GetThreadContext)(HANDLE, LPCONTEXT) = impl_GetThreadContext;

BOOL(WINAPI* __wrap___imp_SetThreadContext)(HANDLE, const CONTEXT*) = impl_SetThreadContext;

}  // extern "C"
