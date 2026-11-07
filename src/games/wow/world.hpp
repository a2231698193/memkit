// wow/world.hpp —— 世界模型（快照 → 语义对象）
//
// 这一层是业务逻辑唯一能看到的东西。它不碰内存，只做转换：
//
//   state::Snapshot（平铺字段，可能 Unknown / Suspect）
//        ↓
//   Player / Target / Camera
//        ↓
//   战斗 / 导航逻辑
//
// 转换时必须保留"未知"语义，不能把 Unknown 当成 0。
#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include "games/wow/entity.hpp"
#include "games/wow/w2s.hpp"
#include "os/gamestate.hpp"

namespace wow {

// 单个数值字段的"读到了"语义
template <class T>
struct Maybe {
    T value{};
    bool known = false;

    explicit operator bool() const { return known; }
    T operator*() const { return value; }
    T value_or(T def) const { return known ? value : def; }
};

struct Player {
    Maybe<Guid> guid;
    Maybe<uint32_t> hp;
    Maybe<uint32_t> hpMax;
    Maybe<uint32_t> mp;
    Maybe<uint32_t> mpMax;
    Maybe<uint32_t> level;
    Maybe<Vec3> pos;
    Maybe<float> facing;
    Maybe<bool> inCombat;
    Maybe<bool> casting;

    bool alive() const { return hp.known && hp.value > 0; }
    float hp_pct() const {
        if (!hp.known || !hpMax.known || hpMax.value == 0) return -1.0f;
        return static_cast<float>(hp.value) / static_cast<float>(hpMax.value) * 100.0f;
    }
    float mp_pct() const {
        if (!mp.known || !mpMax.known || mpMax.value == 0) return -1.0f;
        return static_cast<float>(mp.value) / static_cast<float>(mpMax.value) * 100.0f;
    }
    // 位置是否可用（做距离计算的前提）
    bool has_pos() const { return pos.known; }
};

struct Target {
    Maybe<Guid> guid;
    Maybe<uint32_t> hp;
    Maybe<uint32_t> hpMax;
    Maybe<uint32_t> level;
    Maybe<Vec3> pos;
    Maybe<Reaction> reaction;

    bool exists() const { return guid.known && guid.value != 0; }
    bool alive() const { return hp.known && hp.value > 0; }
    float hp_pct() const {
        if (!hp.known || !hpMax.known || hpMax.value == 0) return -1.0f;
        return static_cast<float>(hp.value) / static_cast<float>(hpMax.value) * 100.0f;
    }
    bool hostile() const {
        return reaction.known && reaction.value == Reaction::Hostile;
    }
    bool has_pos() const { return pos.known; }
};

struct Camera {
    Maybe<Mat4> matrix;
    Maybe<float> fov;
    Screen screen{};

    bool usable() const { return matrix.known && matrix.value.sane() && screen.valid(); }

    bool project(const Vec3& world, Vec2& out) const {
        if (!usable()) return false;
        return world_to_screen_rowmajor(matrix.value, world, screen, out);
    }
};

struct World {
    Player player;
    Target target;
    Camera camera;

    // 汇总健康度
    state::Snapshot::Stats stats;
    bool reliable = false;
};

// ---------- 从快照构造 ----------
namespace detail {

template <class T>
Maybe<T> read_num(const state::Snapshot& s, const std::string& name) {
    Maybe<T> out;
    const auto* f = s.get(name);
    if (!f || !f->known()) return out;
    out.value = static_cast<T>(f->value.as_u64());
    out.known = true;
    return out;
}

inline Maybe<float> read_f32(const state::Snapshot& s, const std::string& name) {
    Maybe<float> out;
    const auto* f = s.get(name);
    if (!f || !f->known()) return out;
    out.value = static_cast<float>(f->value.as_double());
    out.known = true;
    return out;
}

inline Maybe<Vec3> read_vec3(const state::Snapshot& s, const std::string& name) {
    Maybe<Vec3> out;
    const auto* f = s.get(name);
    if (!f || !f->known() || f->value.type != schema::VType::Vec3) return out;
    out.value = {f->value.v.vec3.x, f->value.v.vec3.y, f->value.v.vec3.z};
    out.known = true;
    return out;
}

inline Maybe<Mat4> read_mat4(const state::Snapshot& s, const std::string& name) {
    Maybe<Mat4> out;
    const auto* f = s.get(name);
    if (!f || !f->known() || f->value.type != schema::VType::Mat4) return out;
    Mat4 m;
    for (int i = 0; i < 16; ++i) m.m[i] = f->value.v.mat4.m[i];
    out.value = m;
    out.known = true;
    return out;
}

}  // namespace detail

inline World build_world(const state::Snapshot& s) {
    World w;

    w.player.guid = detail::read_num<Guid>(s, "player.guid");
    w.player.hp = detail::read_num<uint32_t>(s, "player.hp");
    w.player.hpMax = detail::read_num<uint32_t>(s, "player.hp_max");
    w.player.mp = detail::read_num<uint32_t>(s, "player.mp");
    w.player.mpMax = detail::read_num<uint32_t>(s, "player.mp_max");
    w.player.level = detail::read_num<uint32_t>(s, "player.level");
    w.player.pos = detail::read_vec3(s, "player.pos");
    w.player.facing = detail::read_f32(s, "player.facing");

    w.target.guid = detail::read_num<Guid>(s, "target.guid");
    w.target.hp = detail::read_num<uint32_t>(s, "target.hp");
    w.target.hpMax = detail::read_num<uint32_t>(s, "target.hp_max");
    w.target.level = detail::read_num<uint32_t>(s, "target.level");
    w.target.pos = detail::read_vec3(s, "target.pos");

    if (const auto* f = s.get("target.reaction"); f && f->known()) {
        const auto r = static_cast<uint8_t>(f->value.as_u64());
        if (r >= 1 && r <= 3) {
            w.target.reaction.value = static_cast<Reaction>(r);
            w.target.reaction.known = true;
        }
    }

    // 摄像机矩阵：优先 mat4 字段，其次从 chain 地址读
    w.camera.matrix = detail::read_mat4(s, "camera.matrix_data");
    w.camera.fov = detail::read_f32(s, "camera.fov");

    w.stats = s.stats();
    w.reliable = w.stats.reliable();

    return w;
}

}  // namespace wow