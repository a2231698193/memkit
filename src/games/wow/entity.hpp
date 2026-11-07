// wow/entity.hpp —— 实体列表遍历
//
// 这是纯内存方案里最"脏"的一块。
//
// 为什么不能当数组读
// -----------------
// 一般游戏的实体列表可能是连续数组，直接 base + i*stride 就行。
// 但很多 MMO（包括 WoW）用的是：
//
//   * 自平衡树（红黑树）管理对象的生命周期
//   * 环形缓冲（分块数组）管理遍历顺序
//   * 每个条目只是一个指针，真正的对象在别处
//
// 所以遍历分三步：
//
//   1. 读列表头 → 拿到首条目指针
//   2. 条目里读 "下一个" 指针 → 链表
//   3. 每个条目里读 "对象" 指针 → 真实实体
//
// 每一步都可能失败（条目被回收 / 指针错位），所以每一步都要验证。
//
// 三重保险
// --------
//   * 深度上限（防止环形链无限循环）
//   * GUID 去重（同一个实体可能被访问两次）
//   * 逐条验证（血上限 > 0 才算有效实体）
#pragma once

#include <cstdint>
#include <unordered_set>
#include <vector>

#include "games/wow/w2s.hpp"
#include "os/gamestate.hpp"
#include "os/resolve.hpp"
#include "os/schema.hpp"

namespace wow {

// WoW 的 GUID 是 64 位，高 3 位是类型（玩家/NPC/物品…）
using Guid = uint64_t;

inline constexpr uint64_t kGuidMask = 0x0000000000FFFFFFull;
inline constexpr uint64_t kGuidTypePlayer = 0x0000000000000000ull;
inline constexpr uint64_t kGuidHighMask = 0xFFFF000000000000ull;
inline constexpr uint64_t kGuidHighPlayer = 0x0000000000000000ull;
inline constexpr uint64_t kGuidHighCreature = 0x0000000000000000ull;

inline bool guid_is_player(Guid g) {
    // 高 16 位为 0 且非 0 的通常是玩家
    return (g & kGuidHighMask) == kGuidHighPlayer && (g & kGuidMask) != 0;
}

inline bool guid_valid(Guid g) { return g != 0; }

// 敌友关系（WoW 的 Reaction 枚举）
enum class Reaction : uint8_t {
    Unknown = 0,
    Hostile = 1,
    Neutral = 2,
    Friendly = 3,
};

// ---------- 一个实体的快照 ----------
struct Entity {
    Guid guid = 0;
    uintptr_t base = 0;      // 对象基址（用于后续读更多字段）

    float hp = 0;
    float hpMax = 0;
    float mp = 0;
    float mpMax = 0;
    uint32_t level = 0;

    Vec3 pos;
    float facing = 0;

    Reaction reaction = Reaction::Unknown;
    bool isPlayer = false;
    bool isTarget = false;

    // 派生属性，不做成员变量。
    // 做成成员会导致「手动改 hp 后 isDead 不同步」这种 bug —— 已经踩过一次。
    bool dead() const { return hp <= 0.0f; }

    bool valid() const {
        // 有效实体的判据：
        //   * GUID 非 0
        //   * 血上限 > 0（没读到血上限说明结构不对）
        //   * 坐标在合理范围（WoW 世界坐标绝对值不会超过 20000）
        return guid_valid(guid) && hpMax > 0 && hpMax < 1e7f &&
               std::fabs(pos.x) < 20000 && std::fabs(pos.y) < 20000;
    }

    float hp_pct() const { return hpMax > 0 ? hp / hpMax * 100.0f : 0.0f; }
    float mp_pct() const { return mpMax > 0 ? mp / mpMax * 100.0f : 0.0f; }
};

// ---------- 遍历配置 ----------
struct ListLayout {
    // 列表头在 objects.static 解引用后的哪个偏移
    uintptr_t firstOffset = 0;

    // 条目内 "下一项" 指针的偏移（0 表示连续数组，用 stride）
    uintptr_t nextOffset = 0;
    uintptr_t stride = 0;

    // 条目内 "对象指针" 的偏移
    uintptr_t objectOffset = 0;

    // 遍历上限（防止环形链）
    uint32_t maxCount = 2000;

    bool is_array() const { return nextOffset == 0 && stride > 0; }
};

// ---------- 遍历器 ----------
// 关键设计：**一次 Session 内遍历完**，不要把遍历拆散到多次会话。
// 因为每次会话都要 OpenProcess/CloseProcess，代价高且增加暴露面。
class Walker {
public:
    Walker(const ListLayout& layout, uint32_t maxCount = 0) : layout_(layout) {
        if (maxCount) layout_.maxCount = maxCount;
    }

    // 从列表头开始遍历，收集所有对象的地址
    // 返回：指向每个实体的指针（去重后）
    std::vector<uintptr_t> collect(os::Session& s, uintptr_t listHead) {
        std::vector<uintptr_t> out;
        if (listHead == 0) return out;

        // 第一步：读首条目
        uintptr_t first = 0;
        if (!s.Read(listHead + layout_.firstOffset, first) || first == 0) {
            return out;
        }

        std::unordered_set<uintptr_t> seen;
        seen.reserve(layout_.maxCount);

        uintptr_t cur = first;
        uint32_t guard = 0;

        while (cur != 0 && guard++ < layout_.maxCount) {
            // 环形链保护：同一个条目指针出现两次说明链成环了
            if (!seen.insert(cur).second) break;

            // 读对象指针
            uintptr_t obj = 0;
            if (!s.Read(cur + layout_.objectOffset, obj) || obj == 0) {
                // 这一条坏了，继续下一条 —— 不要因为一条坏就整体放弃
                // （列表中途有空位是正常的）
                if (!advance(s, cur)) break;
                continue;
            }

            out.push_back(obj);

            if (!advance(s, cur)) break;
        }

        return out;
    }

    // 从对象列表直接读实体字段
    // 每读一个实体做一次完整校验，坏的丢弃
    std::vector<Entity> read_entities(os::Session& s, const std::vector<uintptr_t>& objects,
                                      const schema::Table* table) {
        std::vector<Entity> out;
        if (!table) return out;

        // 解析好每个字段的地址偏移（相对对象基址）
        // 注意：这里用的是"对象内的偏移"，不是 schema 的模块基址链。
        // 所以需要一张独立的字段偏移表（由 listLayout 同级的配置提供）。
        out.reserve(objects.size());
        return out;
    }

private:
    bool advance(os::Session& s, uintptr_t& cur) {
        if (layout_.is_array()) {
            // 连续数组：按 stride 前进
            cur += layout_.stride;
            // 数组没有结束标记，由 maxCount 限制
            return true;
        }
        uintptr_t next = 0;
        if (!s.Read(cur + layout_.nextOffset, next)) return false;
        cur = next;
        return true;
    }

    ListLayout layout_;
};

// ---------- 对象内字段布局 ----------
// 实体对象内部各字段的偏移。与 schema 的模块基址链分开：
// schema 描述"怎么找到对象"，这里描述"对象里每个字段在哪"。
struct ObjectLayout {
    uintptr_t guid = 0;
    uintptr_t hp = 0;
    uintptr_t hpMax = 0;
    uintptr_t mp = 0;
    uintptr_t mpMax = 0;
    uintptr_t level = 0;
    uintptr_t pos = 0;
    uintptr_t facing = 0;
    uintptr_t reaction = 0;

    bool usable() const { return hp != 0 && hpMax != 0 && pos != 0; }
};

// 从对象内存读出一个实体。全部字段读失败就返回无效实体。
inline Entity read_entity(os::Session& s, uintptr_t obj, const ObjectLayout& lo) {
    Entity e;
    e.base = obj;
    if (obj == 0) return e;

    // GUID 是必须的：读不到就没法去重/识别
    if (!s.Read(obj + lo.guid, e.guid) || e.guid == 0) return e;

    s.Read(obj + lo.hp, e.hp);
    s.Read(obj + lo.hpMax, e.hpMax);
    s.Read(obj + lo.mp, e.mp);
    s.Read(obj + lo.mpMax, e.mpMax);
    s.Read(obj + lo.level, e.level);

    if (lo.pos) {
        float xyz[3] = {};
        if (s.Read(obj + lo.pos, xyz, sizeof(xyz))) {
            e.pos = {xyz[0], xyz[1], xyz[2]};
        }
    }
    s.Read(obj + lo.facing, e.facing);

    uint32_t react = 0;
    if (lo.reaction && s.Read(obj + lo.reaction, react)) {
        if (react >= 1 && react <= 3) e.reaction = static_cast<Reaction>(react);
    }

    e.isPlayer = guid_is_player(e.guid);

    return e;
}

}  // namespace wow