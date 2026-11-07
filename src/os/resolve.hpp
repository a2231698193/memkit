// os/resolve.hpp —— 偏移表执行器（纯内存方案的核心）
//
// 职责：把 schema::Table 的字段声明，翻译成实际的 NtReadVirtualMemory 调用序列，
//      并把结果带着验证状态返回。
//
// 分两层：
//
//   Resolver    负责「解析地址」——多级指针链的每一级解引用
//               地址解析失败（链断了）返回 0，不算错误
//
//   Reader      负责「读值 + 验证」——按 VType 解释字节，跑 Check 断言
//
// 关键设计：所有偏移解析在同一批 Session 里完成，因为地址解析和值读取
// 都需要目标内存，分两批会翻倍句柄开销（而句柄是唯一硬暴露面）。
//
// 缓存策略
// --------
// 多级指针链的中间结果在游戏运行期是稳定的（除了少数会变的结构）。
// 所以 Resolver 缓存「已解析的地址」，只在失效时才重新走链。
//
// 失效判定：
//   * 读值失败（链某级变 0 或不可读）
//   * 显式 invalidate()
//   * 游戏重启（pid 变化）
//
// 这样稳态下每个字段只需 1 次读（读值），而不是 N 次读（走链 + 读值）。
#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

#include "os/process.hpp"
#include "os/scanpattern.hpp"
#include "os/schema.hpp"

namespace resolve {

// ---------- 地址解析缓存 ----------
class AddressCache {
public:
    // 查询已缓存的地址；0 表示未缓存
    uintptr_t get(const std::string& name) const {
        auto it = cache_.find(name);
        return it == cache_.end() ? 0 : it->second;
    }

    void put(const std::string& name, uintptr_t addr) {
        cache_[name] = addr;
        ++hits_new_;
    }

    void invalidate(const std::string& name) { cache_.erase(name); }
    void clear() { cache_.clear(); }
    size_t size() const noexcept { return cache_.size(); }

private:
    std::unordered_map<std::string, uintptr_t> cache_;
    uint32_t hits_new_ = 0;
};

// ---------- 按 VType 解释字节 ----------
struct Value {
    schema::VType type = schema::VType::None;
    union {
        uint64_t u64;
        int64_t i64;
        double f64;
        struct { float x, y, z; } vec3;
        struct { float x, y; } vec2;
        struct { float m[16]; } mat4;   // 行主序，m[row*4+col]
    } v{};
    bool ok = false;

    double as_double() const noexcept {
        switch (type) {
            case schema::VType::U8:
            case schema::VType::U16:
            case schema::VType::U32:
            case schema::VType::U64: return static_cast<double>(v.u64);
            case schema::VType::I32: return static_cast<double>(v.i64);
            case schema::VType::F32:
            case schema::VType::F64: return v.f64;
            default: return 0.0;
        }
    }

    uint64_t as_u64() const noexcept {
        switch (type) {
            case schema::VType::F32:
            case schema::VType::F64: return static_cast<uint64_t>(v.f64);
            default: return v.u64;
        }
    }
};

inline Value decode(const uint8_t* p, schema::VType t) noexcept {
    Value out;
    out.type = t;
    out.ok = true;
    switch (t) {
        case schema::VType::U8: out.v.u64 = *p; break;
        case schema::VType::U16: { uint16_t x; std::memcpy(&x, p, 2); out.v.u64 = x; break; }
        case schema::VType::U32: { uint32_t x; std::memcpy(&x, p, 4); out.v.u64 = x; break; }
        case schema::VType::U64: { uint64_t x; std::memcpy(&x, p, 8); out.v.u64 = x; break; }
        case schema::VType::I32: { int32_t x; std::memcpy(&x, p, 4); out.v.i64 = x; break; }
        case schema::VType::F32: {
            float x; std::memcpy(&x, p, 4);
            out.v.f64 = static_cast<double>(x);
            break;
        }
        case schema::VType::F64: {
            double x; std::memcpy(&x, p, 8);
            out.v.f64 = x;
            break;
        }
        case schema::VType::Vec3: {
            float x, y, z;
            std::memcpy(&x, p + 0, 4);
            std::memcpy(&y, p + 4, 4);
            std::memcpy(&z, p + 8, 4);
            out.v.vec3 = {x, y, z};
            break;
        }
        case schema::VType::Vec2: {
            float x, y;
            std::memcpy(&x, p + 0, 4);
            std::memcpy(&y, p + 4, 4);
            out.v.vec2 = {x, y};
            break;
        }
        case schema::VType::Mat4: {
<<<<<<< HEAD
            // 直接按 16 个 float 读，不区分行/列主序。
            // 内存里就是 16 个连续 float，怎么解释由使用方决定。
=======
            // 直接按 16 个 float 读，不区分行/列主序 —— 由使用方按需转置。
            // 多数游戏引擎内部用列主序（OpenGL 风格），但内存布局就是
            // 16 个连续 float，怎么解释由调用方决定。
>>>>>>> 9168a9d (game/wow-classic: 魔兽世界怀旧服游戏层)
            std::memcpy(out.v.mat4.m, p, 64);
            break;
        }
        default: out.ok = false; break;
    }
    return out;
}

// ---------- 单字段的解析结果 ----------
struct FieldResult {
    std::string name;
    uintptr_t addr = 0;      // 解析出的最终地址
    Value value;             // 读到的值（kind=Chain 时只有 addr）
    bool address_ok = false; // 地址链走通了
    bool value_ok = false;   // 值读到了
    bool check_ok = true;    // 验证断言通过
    bool from_cache = false; // 地址来自缓存
};

// ---------- 解析器 ----------
// 使用方式：
//   Resolver r;
//   r.bind(&table, moduleBase, pid);
//   auto results = r.read_all(session);
class Resolver {
public:
    void bind(const schema::Table* table, uintptr_t moduleBase, DWORD pid,
              size_t moduleSize = 0) {
        table_ = table;
        moduleBase_ = moduleBase;
        moduleSize_ = moduleSize;
        if (pid != pid_) {
            pid_ = pid;
            cache_.clear();   // 换了进程必须清缓存
        }
    }

    void set_module_base(uintptr_t base) {
        if (base != moduleBase_) {
            moduleBase_ = base;
            cache_.clear();   // ASLR 导致基址变了
        }
    }

    const schema::Table* table() const noexcept { return table_; }
    uintptr_t module_base() const noexcept { return moduleBase_; }
    size_t cached() const noexcept { return cache_.size(); }
    void set_module_size(size_t sz) noexcept { moduleSize_ = sz; }
    uint32_t scan_failures() const noexcept { return scanFailures_; }
    uint32_t scan_ambiguous() const noexcept { return scanAmbiguous_; }
    void invalidate_all() { cache_.clear(); }

    // 解析单个字段的最终地址（会用缓存）
    // 返回 0 表示链断了 / 扫描失败
    uintptr_t resolve(os::Session& s, const schema::Field& f) {
        if (moduleBase_ == 0) return 0;

        // ---------- kind == Scan：特征码定位 ----------
        // 优先级最高：有 scanPattern 就不走 offs 链。
        // 结果进缓存，同一进程生命周期内只扫一次。
        if (f.is_scan()) {
            const uintptr_t cachedScan = cache_.get(f.name);
            if (cachedScan != 0) return cachedScan;

            auto r = scan::resolve(s, moduleBase_, moduleSize_, f.scanPattern,
                                   f.scanDeref, f.scanAddend);
            if (!r.ok) {
                // scan::resolve 内部已经拒绝了不唯一的匹配，但保留了 matches 计数。
                // 先判不唯一，再判普通失败 —— 否则永远走不到 ambiguous 分支。
                if (r.matches > 1) {
                    ++scanAmbiguous_;
                } else {
                    ++scanFailures_;
                }
                return 0;
            }

            uint8_t probe = 0;
            if (!s.Read(r.target, &probe, 1)) return 0;

            cache_.put(f.name, r.target);
            return r.target;
        }

        if (f.offs.empty()) return 0;

        // kind=Offset 只有一级，不缓存（本来就是一次加法）
        if (f.kind == schema::Kind::Offset) {
            const uintptr_t addr = moduleBase_ + f.offs[0];
            // 验证可读性
            uint8_t probe = 0;
            return s.Read(addr, &probe, 1) ? addr : 0;
        }

        // 有缓存直接返回
        const uintptr_t cached = cache_.get(f.name);
        if (cached != 0) return cached;

        // 走链：moduleBase + offs[0]，然后逐级解引用 + offs[i]
        uintptr_t cur = moduleBase_;
        for (size_t i = 0; i < f.offs.size(); ++i) {
            cur += f.offs[i];
            if (i + 1 == f.offs.size()) {
                // 最后一级：cur 就是目标地址
                break;
            }
            // 中间级：解引用
            uint64_t next = 0;
            if (!s.Read(cur, next) || next == 0) return 0;
            cur = static_cast<uintptr_t>(next);
        }

        // 目标地址必须可读，否则缓存毒化
        uint8_t probe = 0;
        if (!s.Read(cur, &probe, 1)) return 0;

        cache_.put(f.name, cur);
        return cur;
    }

    // 读单个字段（地址解析 + 读值 + 验证）
    FieldResult read_one(os::Session& s, const schema::Field& f) {
        FieldResult r;
        r.name = f.name;

        if (table_ == nullptr) return r;

        r.from_cache = cache_.get(f.name) != 0;
        r.addr = resolve(s, f);
        if (r.addr == 0) {
            // 链断了：清掉这个字段的缓存，下次重试
            cache_.invalidate(f.name);
            return r;
        }
        r.address_ok = true;

        // kind=Chain 到此为止
        if (f.kind == schema::Kind::Chain) return r;

        // 读值。Mat4 需要 64 字节，所以 buffer 按最大 VType 开
        const size_t sz = schema::vtype_size(f.type);
        if (sz == 0 || sz > 64) return r;

        uint8_t buf[64] = {};
        if (!s.Read(r.addr, buf, sz)) {
            cache_.invalidate(f.name);   // 值读不到说明结构变了
            return r;
        }

        r.value = decode(buf, f.type);
        r.value_ok = r.value.ok;

        // 验证断言
        if (r.value_ok && f.check.op != schema::Check::Op::None) {
            r.check_ok = f.check.eval(r.value.as_double());
            if (!r.check_ok) {
                // 验证失败 = 偏移错位，立刻清缓存强制重新解析
                cache_.invalidate(f.name);
            }
        }

        return r;
    }

    // 读所有字段（按 schema 顺序）
    std::vector<FieldResult> read_all(os::Session& s) {
        std::vector<FieldResult> out;
        if (!table_) return out;
        out.reserve(table_->fields.size());
        for (const auto& f : table_->fields) {
            out.push_back(read_one(s, f));
        }
        return out;
    }

    // 只读指定几个字段（业务层通常只关心少数几个）
    std::vector<FieldResult> read_named(os::Session& s,
                                        const std::vector<std::string>& names) {
        std::vector<FieldResult> out;
        if (!table_) return out;
        out.reserve(names.size());
        for (const auto& n : names) {
            const auto* f = table_->find(n);
            if (f) out.push_back(read_one(s, *f));
        }
        return out;
    }

    // 健康检查：有多少字段解析成功
    struct Health {
        size_t total = 0;
        size_t addr_ok = 0;
        size_t value_ok = 0;
        size_t check_ok = 0;
        bool usable() const noexcept { return total > 0 && check_ok == total; }
        double ratio() const noexcept {
            return total ? static_cast<double>(check_ok) / static_cast<double>(total) : 0.0;
        }
    };

    Health health(os::Session& s) {
        Health h;
        const auto results = read_all(s);
        h.total = results.size();
        for (const auto& r : results) {
            if (r.address_ok) ++h.addr_ok;
            if (r.value_ok) ++h.value_ok;
            if (r.check_ok && r.address_ok) ++h.check_ok;
        }
        return h;
    }

private:
    const schema::Table* table_ = nullptr;
    uintptr_t moduleBase_ = 0;
    size_t moduleSize_ = 0;
    DWORD pid_ = 0;
    AddressCache cache_;
    uint32_t scanFailures_ = 0;
    uint32_t scanAmbiguous_ = 0;
};

}  // namespace resolve
