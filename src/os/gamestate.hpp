// os/gamestate.hpp —— 游戏状态快照（业务层与内存层之间的唯一接口）
//
// 纯内存方案的分层：
//
//   schema（偏移表，会随版本变）
//        ↓
//   resolve（地址解析 + 值读取 + 验证）
//        ↓
//   GameState（本文件：把平铺的字段整理成有语义的快照）
//        ↓
//   业务逻辑（P4，尚未实现）
//
// 为什么要有 GameState 这一层
// --------------------------
// 业务逻辑不应该看到 「offset 0x2C0」这种东西。它应该看到 player.hp。
// 同时 GameState 负责三件业务不关心但不能错的事：
//
//   1. **一致性**：一次快照内所有字段来自同一时刻的同一批 Session，
//      不能一半新一半旧（会导致"血满但其实快死了"这种错误决策）
//   2. **有效性**：字段读失败 / 验证失败时，标成 unknown 而不是 0。
//      0 血和读不到血是完全不同的语义，混在一起会出人命
//   3. **变更检测**：哪些字段自上次快照以来变了（用于事件驱动，减少轮询）
#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "os/process.hpp"
#include "os/resolve.hpp"
#include "os/schema.hpp"

namespace state {

// ---------- 单个字段的状态 ----------
enum class Status : uint8_t {
    Unknown = 0,   // 没读到（链断 / 会话失败）
    Present = 1,   // 读到了且验证通过
    Suspect = 2,   // 读到了但验证失败（偏移可能错位）
};

struct Field {
    Status status = Status::Unknown;
    resolve::Value value;
    uintptr_t addr = 0;

    bool known() const noexcept { return status == Status::Present; }

    double num() const noexcept { return known() ? value.as_double() : 0.0; }
    uint64_t u64() const noexcept { return known() ? value.as_u64() : 0; }
};

// ---------- 一次完整快照 ----------
class Snapshot {
public:
    void put(const std::string& name, Field&& f) { fields_[name] = std::move(f); }
    void put(const std::string& name, const Field& f) { fields_[name] = f; }

    const Field* get(const std::string& name) const {
        auto it = fields_.find(name);
        return it == fields_.end() ? nullptr : &it->second;
    }

    bool known(const std::string& name) const {
        const Field* f = get(name);
        return f && f->known();
    }

    double num(const std::string& name, double def = 0.0) const {
        const Field* f = get(name);
        return (f && f->known()) ? f->value.as_double() : def;
    }

    uint64_t u64(const std::string& name, uint64_t def = 0) const {
        const Field* f = get(name);
        return (f && f->known()) ? f->value.as_u64() : def;
    }

    // vec3 便捷读
    bool vec3(const std::string& name, float& x, float& y, float& z) const {
        const Field* f = get(name);
        if (!f || !f->known() || f->value.type != schema::VType::Vec3) return false;
        x = f->value.v.vec3.x;
        y = f->value.v.vec3.y;
        z = f->value.v.vec3.z;
        return true;
    }

    size_t size() const noexcept { return fields_.size(); }
    const std::unordered_map<std::string, Field>& all() const noexcept { return fields_; }

    // 统计：多少字段有效
    struct Stats {
        size_t total = 0;
        size_t present = 0;
        size_t suspect = 0;
        size_t unknown = 0;
        bool reliable() const noexcept { return total > 0 && unknown == 0 && suspect == 0; }
        double ratio() const noexcept {
            return total ? static_cast<double>(present) / static_cast<double>(total) : 0.0;
        }
    };

    Stats stats() const {
        Stats s;
        s.total = fields_.size();
        for (const auto& kv : fields_) {
            switch (kv.second.status) {
                case Status::Present: ++s.present; break;
                case Status::Suspect: ++s.suspect; break;
                default: ++s.unknown; break;
            }
        }
        return s;
    }

private:
    std::unordered_map<std::string, Field> fields_;
};

// ---------- 变更检测 ----------
// 只报告数值发生变化、或有效性发生变化的字段。
// 业务层用它做事件驱动：不需要每帧比较全部字段。
struct Change {
    std::string name;
    double oldValue = 0;
    double newValue = 0;
    Status oldStatus = Status::Unknown;
    Status newStatus = Status::Unknown;

    bool becameValid() const noexcept {
        return oldStatus != Status::Present && newStatus == Status::Present;
    }
    bool becameInvalid() const noexcept {
        return oldStatus == Status::Present && newStatus != Status::Present;
    }
    double delta() const noexcept { return newValue - oldValue; }
};

inline std::vector<Change> diff(const Snapshot& before, const Snapshot& after) {
    std::vector<Change> out;

    for (const auto& kv : after.all()) {
        const std::string& name = kv.first;
        const Field& nf = kv.second;

        const Field* pf = before.get(name);
        const Status ps = pf ? pf->status : Status::Unknown;
        const double pv = (pf && pf->known()) ? pf->value.as_double() : 0.0;
        const double nv = nf.known() ? nf.value.as_double() : 0.0;

        // 状态变了也算变化（unknown → present 是重要事件）
        if (ps != nf.status) {
            Change c;
            c.name = name;
            c.oldValue = pv;
            c.newValue = nv;
            c.oldStatus = ps;
            c.newStatus = nf.status;
            out.push_back(c);
            continue;
        }

        if (nf.known() && pv != nv) {
            Change c;
            c.name = name;
            c.oldValue = pv;
            c.newValue = nv;
            c.oldStatus = ps;
            c.newStatus = nf.status;
            out.push_back(c);
        }
    }
    return out;
}

// ---------- 快照构造器 ----------
class Builder {
public:
    explicit Builder(resolve::Resolver& r) : r_(r) {}

    // 从 schema 描述的全部字段构造快照
    Snapshot build(os::Session& s) {
        Snapshot snap;
        const auto results = r_.read_all(s);
        for (const auto& fr : results) {
            Field f;
            f.addr = fr.addr;
            if (!fr.address_ok) {
                f.status = Status::Unknown;
            } else if (!fr.value_ok) {
                // kind=Chain 的字段没有值，地址解析成功即为 Present
                const auto* def = r_.table() ? r_.table()->find(fr.name) : nullptr;
                f.status = (def && def->kind == schema::Kind::Chain) ? Status::Present
                                                                     : Status::Unknown;
            } else if (!fr.check_ok) {
                f.status = Status::Suspect;
                f.value = fr.value;
            } else {
                f.status = Status::Present;
                f.value = fr.value;
            }
            snap.put(fr.name, std::move(f));
        }
        return snap;
    }

    // 只读关心的字段（业务层常态）
    Snapshot build_named(os::Session& s, const std::vector<std::string>& names) {
        Snapshot snap;
        const auto results = r_.read_named(s, names);
        for (const auto& fr : results) {
            Field f;
            f.addr = fr.addr;
            if (!fr.address_ok) {
                f.status = Status::Unknown;
            } else if (!fr.value_ok) {
                const auto* def = r_.table() ? r_.table()->find(fr.name) : nullptr;
                f.status = (def && def->kind == schema::Kind::Chain) ? Status::Present
                                                                     : Status::Unknown;
            } else if (!fr.check_ok) {
                f.status = Status::Suspect;
                f.value = fr.value;
            } else {
                f.status = Status::Present;
                f.value = fr.value;
            }
            snap.put(fr.name, std::move(f));
        }
        return snap;
    }

private:
    resolve::Resolver& r_;
};

}  // namespace state
