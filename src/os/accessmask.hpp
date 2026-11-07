// os/accessmask.hpp —— 句柄权限掩码审计
//
// 为什么单独一层
// ==============
// 句柄枚举是外部只读方案唯一的硬暴露面。而游戏看到的不只是"有个句柄"，
// 还有"这个句柄要什么权限"。
//
//   PROCESS_VM_READ                    ← 只读，读一次就够
//   PROCESS_VM_READ | VM_WRITE | ...   ← 明显的写入意图，极端可疑
//
// 如果代码里误用了 kWrite 掩码做纯读取，句柄权限就变成"我想改你的内存"。
// 这在句柄表里一眼可见，且无法事后补救（句柄已经开了）。
//
// 所以要在**请求之前**校验，不是开完再看。
//
// 实测注意
// ========
// 系统会给句柄自动加 SYNCHRONIZE 等位，请求 0x38 实际授予 0x1038。
// 所以不能简单比较 "请求 == 授予"，要检查"请求里有没有危险位"。
//
//   请求 0x00000038 (VM_READ|VM_WRITE|VM_OPERATION)
//   授予 0x00001038 (+SYNCHRONIZE 0x100000 的低位部分)
//
// 判定方式：只看请求掩码本身，不问授予结果。
#pragma once

#include <windows.h>

#include <cstdint>

namespace access {

// ---------- 危险权限位 ----------
// 每多一位，句柄在对方眼里就多一分"恶意"
enum : ACCESS_MASK {
    // 读内存。纯读取方案唯一需要的进程权限。
    kRead = PROCESS_VM_READ,

    // 查询基本信息。配合读内存用于确认 pid / 会话。
    // QUERY_LIMITED 比 QUERY_FULL 权限更低，也更不显眼。
    kQuery = PROCESS_QUERY_LIMITED_INFORMATION,

    // 以下全部属于"纯读取不需要"
    kWrite = PROCESS_VM_WRITE,           // 写内存
    kOperation = PROCESS_VM_OPERATION,   // 改页属性 / 分配
    kCreateThread = PROCESS_CREATE_THREAD,   // 注入
    kDupHandle = PROCESS_DUP_HANDLE,
    kSetInfo = PROCESS_SET_INFORMATION,
    kSuspendResume = PROCESS_SUSPEND_RESUME,
    kTerminate = PROCESS_TERMINATE,
};

// 纯读取允许的掩码：只有这两位
inline constexpr ACCESS_MASK kPureRead = kRead | kQuery;

// 映射/写入场景需要的最小集合（仅 manualmap 用）
inline constexpr ACCESS_MASK kMapNeeded = PROCESS_VM_READ | PROCESS_VM_WRITE |
                                          PROCESS_VM_OPERATION |
                                          PROCESS_QUERY_LIMITED_INFORMATION;

// ---------- 校验 ----------
struct Verdict {
    bool ok = false;
    ACCESS_MASK badBits = 0;      // 越权的位
    const char* reason = "";
};

// 检查一个掩码是否"只读安全"
// strict: true = 只允许 kPureRead 的子集；false = 允许 kMapNeeded 范围内
inline Verdict check_readonly(ACCESS_MASK mask, bool allow_map = false) noexcept {
    Verdict v;
    const ACCESS_MASK allowed = allow_map ? kMapNeeded : kPureRead;

    // 越权位：请求了 allowed 之外的东西
    const ACCESS_MASK bad = mask & ~allowed;
    if (bad != 0) {
        v.ok = false;
        v.badBits = bad;
        v.reason = "请求了纯读取不需要的权限";
        return v;
    }

    // 额外检查：即使 allow_map，也绝不允许这些
    const ACCESS_MASK alwaysForbidden =
        PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE | PROCESS_TERMINATE |
        PROCESS_SUSPEND_RESUME | PROCESS_SET_INFORMATION | PROCESS_CREATE_PROCESS |
        PROCESS_VM_READ * 0 | WRITE_DAC | WRITE_OWNER;

    if ((mask & alwaysForbidden) != 0) {
        v.ok = false;
        v.badBits = mask & alwaysForbidden;
        v.reason = "包含注入/破坏类权限";
        return v;
    }

    v.ok = true;
    v.reason = "仅读权限";
    return v;
}

// 生成"最小可用"掩码：给定想做的事，只给够用的位
enum class Intent : uint8_t {
    ReadOnly = 0,   // 只读内存
    MapImage = 1,   // 手工映射（需要写 + 改权限）
};

inline ACCESS_MASK minimal_mask(Intent i) noexcept {
    switch (i) {
        case Intent::ReadOnly: return kPureRead;
        case Intent::MapImage: return kMapNeeded;
    }
    return kPureRead;
}

// ---------- 权限位的可读名字 ----------
// 用于日志/诊断（不进正式二进制，见下面的编译开关）
inline const char* bit_name(ACCESS_MASK bit) noexcept {
    switch (bit) {
        case PROCESS_VM_READ: return "VM_READ";
        case PROCESS_VM_WRITE: return "VM_WRITE";
        case PROCESS_VM_OPERATION: return "VM_OPERATION";
        case PROCESS_QUERY_INFORMATION: return "QUERY_FULL";
        case PROCESS_QUERY_LIMITED_INFORMATION: return "QUERY_LIMITED";
        case PROCESS_CREATE_THREAD: return "CREATE_THREAD";
        case PROCESS_DUP_HANDLE: return "DUP_HANDLE";
        case PROCESS_TERMINATE: return "TERMINATE";
        case PROCESS_SUSPEND_RESUME: return "SUSPEND_RESUME";
        case PROCESS_SET_INFORMATION: return "SET_INFORMATION";
        case SYNCHRONIZE: return "SYNCHRONIZE";
        default: return "?";
    }
}

// 统计一个掩码里有多少个"危险位"
inline int danger_count(ACCESS_MASK mask) noexcept {
    const ACCESS_MASK dangerous = PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
                                  PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE |
                                  PROCESS_TERMINATE | PROCESS_SUSPEND_RESUME |
                                  PROCESS_SET_INFORMATION;
    int n = 0;
    for (ACCESS_MASK b = 1; b != 0 && b <= PROCESS_ALL_ACCESS; b <<= 1) {
        if ((dangerous & b) && (mask & b)) ++n;
    }
    return n;
}

// 评分：0 = 最干净，越大越可疑。用于运行时自检断言。
inline int suspicion_score(ACCESS_MASK mask) noexcept {
    int score = 0;
    if (mask & PROCESS_VM_WRITE) score += 40;
    if (mask & PROCESS_VM_OPERATION) score += 30;
    if (mask & PROCESS_CREATE_THREAD) score += 100;
    if (mask & PROCESS_DUP_HANDLE) score += 50;
    if (mask & PROCESS_TERMINATE) score += 30;
    if (mask & PROCESS_SUSPEND_RESUME) score += 20;
    if (mask & PROCESS_SET_INFORMATION) score += 20;
    if (mask == PROCESS_ALL_ACCESS) score += 200;
    if (mask & PROCESS_QUERY_INFORMATION) score += 5;   // 比 LIMITED 显眼一点
    return score;
}

}  // namespace access
