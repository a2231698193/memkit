// os/task.hpp —— 任务队列（批处理调度器的输入）
//
// 设计目标：
//   * 任务可以被「序列化 / 重放」——便于离线调试，不必连游戏
//   * 一个批次（Batch）内共享同一个 Session，会话开销摊薄
//   * 任务本身只描述「读哪里、读多少、写到哪」，不携带业务判断
//
// 任务类型：
//   Read      单次读
//   Chain     多级指针链
//   Module    读目标模块基址处的字节（用于签名校验）
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "os/process.hpp"

namespace os {

enum class TaskKind : uint8_t {
    Read = 0,
    Chain = 1,
    Probe = 2,
};

struct Task {
    TaskKind kind = TaskKind::Read;
    uintptr_t addr = 0;          // Read/Probe: 绝对地址；Chain: 起点
    uint16_t size = 0;           // Read/Probe: 读取字节数（<= 512）
    uint16_t id = 0;             // 调用方自定义标签，结果按 id 回填
    std::vector<uintptr_t> offs; // Chain: 偏移序列
};

struct TaskResult {
    uint16_t id = 0;
    bool ok = false;
    std::vector<uint8_t> bytes;  // Read/Probe
    uintptr_t resolved = 0;      // Chain
};

inline constexpr uint16_t kMaxTaskRead = 512;
inline constexpr size_t kMaxChainDepth = 8;
inline constexpr size_t kMaxBatchTasks = 32;

// 一个批次：同一 Session 内顺序执行，任一失败不影响后续
struct Batch {
    std::vector<Task> tasks;

    bool empty() const noexcept { return tasks.empty(); }
    void clear() noexcept { tasks.clear(); }

    void add(Task&& t) {
        if (tasks.size() < kMaxBatchTasks) tasks.push_back(std::move(t));
    }

    void add_read(uintptr_t addr, uint16_t size, uint16_t id) {
        Task t;
        t.kind = TaskKind::Read;
        t.addr = addr;
        t.size = size > kMaxTaskRead ? kMaxTaskRead : size;
        t.id = id;
        add(std::move(t));
    }

    void add_chain(uintptr_t base, const uintptr_t* offs, size_t n, uint16_t id) {
        if (n == 0 || n > kMaxChainDepth) return;
        Task t;
        t.kind = TaskKind::Chain;
        t.addr = base;
        t.id = id;
        t.offs.assign(offs, offs + n);
        add(std::move(t));
    }

    void add_probe(uintptr_t addr, uint16_t size, uint16_t id) {
        Task t;
        t.kind = TaskKind::Probe;
        t.addr = addr;
        t.size = size > kMaxTaskRead ? kMaxTaskRead : size;
        t.id = id;
        add(std::move(t));
    }
};

// 在会话内执行单个任务
inline TaskResult execute(Session& s, const Task& t) {
    TaskResult r;
    r.id = t.id;

    switch (t.kind) {
        case TaskKind::Read: {
            if (t.size == 0 || t.size > kMaxTaskRead) return r;
            r.bytes.resize(t.size);
            r.ok = s.Read(t.addr, r.bytes.data(), t.size);
            if (!r.ok) r.bytes.clear();
            break;
        }
        case TaskKind::Probe: {
            if (t.size == 0 || t.size > kMaxTaskRead) return r;
            r.bytes.resize(t.size);
            r.ok = s.Read(t.addr, r.bytes.data(), t.size);
            if (!r.ok) r.bytes.clear();
            break;
        }
        case TaskKind::Chain: {
            uintptr_t out = 0;
            r.ok = s.Chain(t.addr, t.offs.data(), t.offs.size(), out);
            if (r.ok) r.resolved = out;
            break;
        }
    }
    return r;
}

// 会话内执行整批
inline std::vector<TaskResult> execute(Session& s, const Batch& b) {
    std::vector<TaskResult> out;
    out.reserve(b.tasks.size());
    for (const auto& t : b.tasks) {
        out.push_back(execute(s, t));
        // 会话已超时：剩余任务直接标失败，不再尝试
        if (!s.alive()) {
            for (size_t i = out.size(); i < b.tasks.size(); ++i) {
                TaskResult dead;
                dead.id = b.tasks[i].id;
                dead.ok = false;
                out.push_back(std::move(dead));
            }
            break;
        }
    }
    return out;
}

}  // namespace os
