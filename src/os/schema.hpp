// os/schema.hpp —— 偏移表（纯内存方案的核心数据）
//
// 这是整个纯内存方案里**唯一会随游戏版本变化**的东西，所以单独隔离成一层，
// 让框架代码完全不感知具体偏移。
//
// 设计目标：
//   1. 偏移表可以被序列化 → 自定义格式文本，方便手动编辑 / 版本切换
//   2. 每条偏移带「验证期望值」 → 读出来的值不对就说明版本变了，能立刻发现
//   3. 支持多版本共存 → 按 exe 的 PE 时间戳自动选表
//   4. 不落明文 → 用 cfg 层加密
//
// 关于「为什么一定要验证」
// -----------------------
// 版本更新后偏移错位，程序不会崩，只会读到垃圾数据 —— 然后基于垃圾数据
// 做出错误决策（比如以为血满但其实快死了，或者走去撞墙）。
// 这是 bot 最容易出问题也最难查的地方。
//
// 所以每条偏移都可以声明 verification：读到的值必须落在某个范围或等于某个值。
// 验证失败时整个表标记为 invalid，业务层拒绝工作，而不是带着错数据跑。
#pragma once

#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

#include "common/hash.hpp"

namespace schema {

// ---------- 偏移条目 ----------
enum class Kind : uint8_t {
    Chain = 0,   // 多级指针链，结果是地址
    Value = 1,   // 多级指针链 + 最终读值
    Offset = 2,  // 单级：基址 + offset
    Scan = 3,    // AOB 特征码扫描，启动时现算地址
};

enum class VType : uint8_t {
    None = 0,
    U8 = 1, U16 = 2, U32 = 3, U64 = 4,
    I32 = 5,
    F32 = 6, F64 = 7,
    Vec3 = 8,   // 3 个 float
    Mat4 = 9,   // 4x4 矩阵，16 个 float（投影必须）
    Vec2 = 10,  // 2 个 float
};

inline size_t vtype_size(VType t) noexcept {
    switch (t) {
        case VType::U8: return 1;
        case VType::U16: return 2;
        case VType::U32: return 4;
        case VType::U64: return 8;
        case VType::I32: return 4;
        case VType::F32: return 4;
        case VType::F64: return 8;
        case VType::Vec3: return 12;
        case VType::Mat4: return 64;
        case VType::Vec2: return 8;
        default: return 0;
    }
}

// 验证断言：读出来的值必须满足其中之一
struct Check {
    enum class Op : uint8_t { None = 0, Eq, Ne, Le, Ge, InRange } op = Op::None;
    double a = 0;   // Eq/Ne/Le/Ge 的比较值；InRange 的下界
    double b = 0;   // InRange 的上界

    bool eval(double v) const noexcept {
        switch (op) {
            case Op::None: return true;
            case Op::Eq: return v == a;
            case Op::Ne: return v != a;
            case Op::Le: return v <= a;
            case Op::Ge: return v >= a;
            case Op::InRange: return v >= a && v <= b;
        }
        return true;
    }
};

struct Field {
    std::string name;       // "player.hp"
    Kind kind = Kind::Value;
    VType type = VType::U32;
    std::vector<uintptr_t> offs;  // 偏移链（相对模块基址的首项，其余为解引用后加）
    Check check;            // 验证断言
    std::string note;       // 备注（怎么找到的、从哪来的）

    // ---------- kind == Scan 专用 ----------
    //
    // 用特征码定位地址，而不是硬编码偏移。版本更新后只要特征码还有效，
    // 偏移自动重算，不用改表。
    //
    // scanPattern 为空表示这个字段用 offs（普通字段）。
    // 非空时 offs 被忽略，地址 = 扫描结果 + scanAddend（可选再解引用）。
    std::string scanPattern;   // "48 8B 05 ?? ?? ?? ?? 33 DB"
    int64_t scanAddend = 0;    // 扫描结果再叠加的偏移（比如 -0x8）
    bool scanDeref = false;    // true = 扫描结果再解引用一次

    bool is_scan() const noexcept { return !scanPattern.empty(); }
};

// ---------- 一张表 ----------
struct Table {
    std::string game = "mygame";
    std::string build;           // 客户端 build 号，例如 "1.15.4.56008"
    uint32_t exe_timestamp = 0;  // PE TimeDateStamp，用于自动匹配
    uint32_t module_size = 0;    // 模块大小，辅助校验
    std::vector<Field> fields;

    const Field* find(const std::string& name) const {
        for (const auto& f : fields) {
            if (f.name == name) return &f;
        }
        return nullptr;
    }
};

// ---------- 文本格式（便于手工编辑 + diff）----------
//
// 格式刻意做成一行一条，便于版本对比：
//
//   # 注释
//   !game        mygame
//   !build       1.15.4.56008
//   !timestamp   0x63A1B2C3
//   !modsize     0x2A10000
//
//   # name              kind   type   offs                  check
//   player.base         chain  u64    0x2F1A3B0             -
//   player.hp           value  u32    0x2F1A3B0,0x10,0x2C0  inrange 1 100
//   player.pos          value  vec3   0x2F1A3B0,0x10,0x30   -
//
inline const char* kind_name(Kind k) noexcept {
    switch (k) {
        case Kind::Chain: return "chain";
        case Kind::Value: return "value";
        case Kind::Offset: return "offset";
        case Kind::Scan: return "scan";
    }
    return "value";
}

inline const char* vtype_name(VType t) noexcept {
    switch (t) {
        case VType::U8: return "u8";
        case VType::U16: return "u16";
        case VType::U32: return "u32";
        case VType::U64: return "u64";
        case VType::I32: return "i32";
        case VType::F32: return "f32";
        case VType::F64: return "f64";
        case VType::Vec3: return "vec3";
        case VType::Mat4: return "mat4";
        case VType::Vec2: return "vec2";
        default: return "-";
    }
}

inline Kind parse_kind(const std::string& s) noexcept {
    if (s == "chain") return Kind::Chain;
    if (s == "offset") return Kind::Offset;
    if (s == "scan") return Kind::Scan;
    return Kind::Value;
}

inline VType parse_vtype(const std::string& s) noexcept {
    if (s == "u8") return VType::U8;
    if (s == "u16") return VType::U16;
    if (s == "u32") return VType::U32;
    if (s == "u64") return VType::U64;
    if (s == "i32") return VType::I32;
    if (s == "f32") return VType::F32;
    if (s == "f64") return VType::F64;
    if (s == "vec3") return VType::Vec3;
    if (s == "mat4") return VType::Mat4;
    if (s == "vec2") return VType::Vec2;
    return VType::None;
}

// 极简 tokenizer：按空白切分，支持 # 行注释
namespace detail {

struct Tokens {
    std::vector<std::string> words;
    std::string comment;   // '#' 之后的原始内容（不含 #，已 trim）
};

inline std::string trim(const std::string& s) {
    size_t b = 0, e = s.size();
    while (b < e && (s[b] == ' ' || s[b] == '\t')) ++b;
    while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t' || s[e - 1] == '\r')) --e;
    return s.substr(b, e - b);
}

inline Tokens tokenize(const std::string& line) {
    Tokens out;
    std::string cur;
    for (size_t i = 0; i < line.size(); ++i) {
        const char c = line[i];
        if (c == '#') {
            out.comment = trim(line.substr(i + 1));
            break;
        }
        if (c == ' ' || c == '\t' || c == '\r') {
            if (!cur.empty()) { out.words.push_back(cur); cur.clear(); }
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) out.words.push_back(cur);
    return out;
}

inline uintptr_t parse_hex(const std::string& s) {
    return static_cast<uintptr_t>(strtoull(s.c_str(), nullptr, 0));
}

// "0x100,0x20,0x30" → [0x100, 0x20, 0x30]
inline std::vector<uintptr_t> parse_chain(const std::string& s) {
    std::vector<uintptr_t> out;
    std::string cur;
    for (char c : s) {
        if (c == ',') {
            if (!cur.empty()) { out.push_back(parse_hex(cur)); cur.clear(); }
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) out.push_back(parse_hex(cur));
    return out;
}

}  // namespace detail

// 序列化
inline std::string serialize(const Table& t) {
    std::string out;
    out.reserve(4096);

    char buf[512];
    out += "# memkit offset table\n";
    std::snprintf(buf, sizeof(buf), "!game      %s\n", t.game.c_str());
    out += buf;
    std::snprintf(buf, sizeof(buf), "!build     %s\n", t.build.c_str());
    out += buf;
    std::snprintf(buf, sizeof(buf), "!timestamp 0x%08X\n", t.exe_timestamp);
    out += buf;
    std::snprintf(buf, sizeof(buf), "!modsize   0x%X\n\n", t.module_size);
    out += buf;

    out += "# name                kind    type   offs                     check\n";
    for (const auto& f : t.fields) {
        std::string chain;
        for (size_t i = 0; i < f.offs.size(); ++i) {
            if (i) chain.push_back(',');
            std::snprintf(buf, sizeof(buf), "0x%llX",
                          (unsigned long long)f.offs[i]);
            chain += buf;
        }
        if (chain.empty()) chain = "-";

        std::string chk = "-";
        switch (f.check.op) {
            case Check::Op::Eq:
                std::snprintf(buf, sizeof(buf), "eq %.6g", f.check.a); chk = buf; break;
            case Check::Op::Ne:
                std::snprintf(buf, sizeof(buf), "ne %.6g", f.check.a); chk = buf; break;
            case Check::Op::Le:
                std::snprintf(buf, sizeof(buf), "le %.6g", f.check.a); chk = buf; break;
            case Check::Op::Ge:
                std::snprintf(buf, sizeof(buf), "ge %.6g", f.check.a); chk = buf; break;
            case Check::Op::InRange:
                std::snprintf(buf, sizeof(buf), "inrange %.6g %.6g", f.check.a, f.check.b);
                chk = buf;
                break;
            default: break;
        }

        std::snprintf(buf, sizeof(buf), "%-20s %-7s %-6s %-24s %s",
                      f.name.c_str(), kind_name(f.kind), vtype_name(f.type),
                      chain.c_str(), chk.c_str());
        out += buf;

        // scan 字段额外输出特征码与修饰符
        // 格式： scan "<pattern>" [deref] [<addend>]
        if (f.kind == Kind::Scan) {
            out += "  scan ";
            out += f.scanPattern.empty() ? std::string("-") : f.scanPattern;
            if (f.scanDeref) out += " deref";
            if (f.scanAddend != 0) {
                std::snprintf(buf, sizeof(buf), " %lld",
                              static_cast<long long>(f.scanAddend));
                out += buf;
            }
        }

        if (!f.note.empty()) {
            out += "  # ";
            out += f.note;
        }
        out += '\n';
    }
    return out;
}

// 反序列化。返回 false 表示有语法错误，errLine 指出行号。
inline bool parse(const std::string& text, Table& out, int* errLine = nullptr) {
    out = Table{};
    int lineNo = 0;

    size_t pos = 0;
    while (pos <= text.size()) {
        size_t nl = text.find('\n', pos);
        const std::string line = text.substr(pos, (nl == std::string::npos) ? std::string::npos
                                                                          : nl - pos);
        if (nl == std::string::npos) pos = text.size() + 1;
        else pos = nl + 1;
        ++lineNo;

        const auto tks = detail::tokenize(line);
        const auto& tok = tks.words;
        if (tok.empty()) continue;

        // 元数据行：即使值为空也要吃棓，不能落到字段解析
        // （旧版本 !build 为空时会报 bline 错误）
        if (!tok[0].empty() && tok[0][0] == '!') {
            if (tok[0] == "!game" && tok.size() >= 2) {
                out.game = tok[1];
            } else if (tok[0] == "!build" && tok.size() >= 2) {
                out.build = tok[1];
            } else if (tok[0] == "!timestamp" && tok.size() >= 2) {
                out.exe_timestamp = static_cast<uint32_t>(detail::parse_hex(tok[1]));
            } else if (tok[0] == "!modsize" && tok.size() >= 2) {
                out.module_size = static_cast<uint32_t>(detail::parse_hex(tok[1]));
            }
            continue;
        }

        // 字段行：name kind type offs [check] [scan <pattern> [deref] [addend]]
        if (tok.size() < 4) {
            if (errLine) *errLine = lineNo;
            return false;
        }

        Field f;
        f.name = tok[0];
        f.kind = parse_kind(tok[1]);
        f.type = parse_vtype(tok[2]);
        if (tok[3] != "-") f.offs = detail::parse_chain(tok[3]);

        // 从 index 4 开始循环处理 check 与 scan。
        //
        // 两种顺序都要支持：
        //   ... inrange 1 100 scan <pattern> deref -8     （序列化输出顺序）
        //   ... scan <pattern> ge 1                        （手写更自然）
        //
        // 之前写成"先 check 后 scan"的两段式，导致 scan 后面的 check 被忽略。
        size_t idx = 4;
        while (idx < tok.size()) {
            const std::string& tk = tok[idx];

            if (tk == "scan") {
                ++idx;
                if (idx < tok.size() && tok[idx] != "-") f.scanPattern = tok[idx];
                ++idx;
                // deref / addend 可选
                while (idx < tok.size()) {
                    if (tok[idx] == "deref") {
                        f.scanDeref = true;
                        ++idx;
                    } else if (tok[idx] == "-" || tok[idx] == "eq" || tok[idx] == "ne" ||
                               tok[idx] == "le" || tok[idx] == "ge" || tok[idx] == "inrange") {
                        break;   // 遇到下一个 check，跳出
                    } else {
                        f.scanAddend = strtoll(tok[idx].c_str(), nullptr, 0);
                        ++idx;
                        break;
                    }
                }
                if (!f.scanPattern.empty()) f.kind = Kind::Scan;
                continue;
            }

            if (tk == "eq" && idx + 1 < tok.size()) {
                f.check.op = Check::Op::Eq;
                f.check.a = strtod(tok[idx + 1].c_str(), nullptr);
                idx += 2;
                continue;
            }
            if (tk == "ne" && idx + 1 < tok.size()) {
                f.check.op = Check::Op::Ne;
                f.check.a = strtod(tok[idx + 1].c_str(), nullptr);
                idx += 2;
                continue;
            }
            if (tk == "le" && idx + 1 < tok.size()) {
                f.check.op = Check::Op::Le;
                f.check.a = strtod(tok[idx + 1].c_str(), nullptr);
                idx += 2;
                continue;
            }
            if (tk == "ge" && idx + 1 < tok.size()) {
                f.check.op = Check::Op::Ge;
                f.check.a = strtod(tok[idx + 1].c_str(), nullptr);
                idx += 2;
                continue;
            }
            if (tk == "inrange" && idx + 2 < tok.size()) {
                f.check.op = Check::Op::InRange;
                f.check.a = strtod(tok[idx + 1].c_str(), nullptr);
                f.check.b = strtod(tok[idx + 2].c_str(), nullptr);
                idx += 3;
                continue;
            }
            if (tk == "-") {
                ++idx;
                continue;
            }

            // 未知 token，跳过（容错）
            ++idx;
        }

        f.note = tks.comment;
        out.fields.push_back(std::move(f));
    }

    return true;
}

// ---------- 多版本注册表 ----------
// 按 (game, exe_timestamp) 查找；找不到就按 build 字符串匹配
class Registry {
public:
    void add(Table&& t) { tables_.push_back(std::move(t)); }

    // 优先按 PE 时间戳匹配，其次按 build 字符串
    const Table* match(uint32_t exeTimestamp, const std::string& build) const {
        for (const auto& t : tables_) {
            if (t.exe_timestamp != 0 && t.exe_timestamp == exeTimestamp) return &t;
        }
        if (!build.empty()) {
            for (const auto& t : tables_) {
                if (t.build == build) return &t;
            }
        }
        return nullptr;
    }

    size_t size() const noexcept { return tables_.size(); }
    const std::vector<Table>& all() const noexcept { return tables_; }

private:
    std::vector<Table> tables_;
};

}  // namespace schema
