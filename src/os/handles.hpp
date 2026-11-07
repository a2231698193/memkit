// os/handles.hpp —— 句柄审计器
//
// 作用：回答一个只有自己知道答案的问题——
//      "本进程此刻是否持有指向目标进程的句柄？"
// 这是外部脚本唯一的硬暴露面：游戏侧可用
//      NtQuerySystemInformation(SystemExtendedHandleInformation)
// 枚举全系统句柄，筛出 ObjectTypeIndex==Process 且 Object 指向自己的条目，
// 直接读出持有者 PID。所以自身必须能随时自证"我手上是干净的"。
//
// 实现要点：
//   * 类型索引校准：先 NtOpenProcess 自己一次，在全表里找到那个句柄的
//     ObjectTypeIndex，即为 Process 类型索引；随后关掉。避免硬编码
//     （各版本 Windows 的类型编号会变）。
//   * 判定目标：拿到 Process 类型的句柄后，直接在自身进程内对该句柄调
//     NtQueryInformationProcess(ProcessBasicInformation)，比对 UniqueProcessId。
//     不需要 DuplicateHandle——句柄本来就在自家句柄表里。
//   * 全程走 ntdll 动态解析，导入表零污染。
#pragma once

#include <windows.h>
#include <winternl.h>

#include <cstddef>
#include <cstdint>
#include <vector>

#include "common/hash.hpp"
#include "os/process.hpp"
#include "stealth/api.hpp"

namespace os {

// ---- 系统全表结构（winternl.h 未收录，自行定义）----
#pragma pack(push, 8)
struct SysHandleEntryEx {
    void*      Object;             // 对象体指针（内核地址，仅用于比较）
    ULONG_PTR  UniqueProcessId;    // 持有者 PID
    HANDLE     HandleValue;        // 句柄值
    ULONG      GrantedAccess;
    USHORT     CreatorBackTraceIndex;
    USHORT     ObjectTypeIndex;
    ULONG      HandleAttributes;
    ULONG      Reserved;
};
#pragma pack(pop)

struct SysHandleInfoEx {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;          // 内核保留字段，不可省略（漏掉会让整表错位 8 字节）
    SysHandleEntryEx Handles[1];
};

inline constexpr ULONG kSystemExtendedHandleInformation = 64;

using NtQuerySystemInformationFn = LONG(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
using NtQueryInformationProcessFn =
    LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

inline NtQuerySystemInformationFn nt_query_sysinfo() noexcept {
    static auto fn = api::get<NtQuerySystemInformationFn>(
        api::mod::ntdll, hash::ascii("NtQuerySystemInformation"));
    return fn;
}

inline NtQueryInformationProcessFn nt_query_process() noexcept {
    static auto fn = api::get<NtQueryInformationProcessFn>(
        api::mod::ntdll, hash::ascii("NtQueryInformationProcess"));
    return fn;
}

// 拉取全系统句柄表的快照（自扩容，返回连续缓冲区）
inline bool snapshot_handles(std::vector<uint8_t>& buf) {
    const auto qsi = nt_query_sysinfo();
    if (!qsi) return false;

    ULONG need = 0;
    qsi(kSystemExtendedHandleInformation, nullptr, 0, &need);
    if (need < 0x10000) need = 0x10000;

    for (int attempt = 0; attempt < 6; ++attempt) {
        buf.resize(static_cast<size_t>(need) + 0x10000);
        ULONG got = 0;
        const LONG st = qsi(kSystemExtendedHandleInformation, buf.data(),
                            static_cast<ULONG>(buf.size()), &got);
        if (st >= 0) {
            buf.resize(got ? got : buf.size());
            return true;
        }
        if (st != static_cast<LONG>(0xC0000004)) return false;  // 非"长度不足"
        need = got ? got : need * 2;
    }
    return false;
}

// 类型索引缓存：首次调用时自我校准
inline uint16_t process_type_index() noexcept {
    static uint16_t idx = []() -> uint16_t {
        // 用一个只带最小权限的自身句柄做标定
        HANDLE h = nullptr;
        const auto open = nt_open_process();
        if (!open) return 0xFFFF;

        OBJECT_ATTRIBUTES oa{};
        oa.Length = sizeof(oa);
        CLIENT_ID cid{};
        cid.UniqueProcess = reinterpret_cast<HANDLE>(
            static_cast<uintptr_t>(GetCurrentProcessId()));
        if (open(&h, PROCESS_QUERY_LIMITED_INFORMATION, &oa, &cid) < 0 || !h) return 0xFFFF;

        uint16_t found = 0xFFFF;
        std::vector<uint8_t> buf;
        if (snapshot_handles(buf)) {
            const auto* info = reinterpret_cast<const SysHandleInfoEx*>(buf.data());
            const ULONG_PTR self = GetCurrentProcessId();
            for (ULONG_PTR i = 0; i < info->NumberOfHandles; ++i) {
                const auto& e = info->Handles[i];
                if (e.UniqueProcessId == self && e.HandleValue == h) {
                    found = e.ObjectTypeIndex;
                    break;
                }
            }
        }

        const auto close = nt_close();
        if (close) close(h);
        return found;
    }();
    return idx;
}

struct AuditResult {
    bool ok = false;             // 审计是否成功执行（false 表示工具本身失败）
    uint16_t type_index = 0xFFFF;
    uint32_t self_process_handles = 0;   // 自身持有的 Process 类型句柄总数
    uint32_t target_handles = 0;         // 其中指向目标 PID 的数量
    uint32_t unknown = 0;                // 查询失败、无法判定的数量
};

// 审计：统计自身持有的 Process 类型句柄，并挑出指向 targetPid 的条目
inline AuditResult audit_handles(DWORD targetPid) {
    AuditResult r;
    const uint16_t typeIdx = process_type_index();
    r.type_index = typeIdx;
    if (typeIdx == 0xFFFF) return r;

    std::vector<uint8_t> buf;
    if (!snapshot_handles(buf)) return r;

    const auto qp = nt_query_process();
    const ULONG_PTR self = GetCurrentProcessId();
    const auto* info = reinterpret_cast<const SysHandleInfoEx*>(buf.data());

    for (ULONG_PTR i = 0; i < info->NumberOfHandles; ++i) {
        const auto& e = info->Handles[i];
        if (e.UniqueProcessId != self) continue;
        if (e.ObjectTypeIndex != typeIdx) continue;

        ++r.self_process_handles;
        if (!qp) continue;

        // 伪句柄（GetCurrentProcess/GetCurrentThread 返回的 -1/-2）不对应真实对象，跳过
        if (e.HandleValue == reinterpret_cast<HANDLE>(static_cast<uintptr_t>(-1)) ||
            e.HandleValue == reinterpret_cast<HANDLE>(static_cast<uintptr_t>(-2))) {
            continue;
        }

        // 句柄本就属于自身，直接查询即可
        struct {
            PVOID Reserved1;
            PVOID PebBaseAddress;
            PVOID Reserved2[2];
            ULONG_PTR UniqueProcessId;
            PVOID Reserved3;
        } pbi{};

        ULONG ret = 0;
        if (qp(e.HandleValue, 0 /*ProcessBasicInformation*/, &pbi, sizeof(pbi), &ret) < 0) {
            ++r.unknown;
            continue;
        }
        if (static_cast<DWORD>(pbi.UniqueProcessId) == targetPid) ++r.target_handles;
    }

    r.ok = true;
    return r;
}

// 便捷判定：干净（无任何指向目标的句柄）
inline bool clean_of(DWORD targetPid) {
    const AuditResult a = audit_handles(targetPid);
    return a.ok && a.target_handles == 0;
}

}  // namespace os
