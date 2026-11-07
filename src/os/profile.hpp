// os/profile.hpp —— 目标描述（把"哪个游戏"从代码里拿出去）
//
// 框架本身不认识任何具体游戏。游戏相关的三样东西全都在这份 profile 里：
//
//   1. 目标进程名（exe）
//   2. 目标模块名（通常是 exe 本身，但也可能是主 DLL）
//   3. 用哪张偏移表（schema::Table 的 game/build 标识）
//
// 除此之外还有运行参数：轮询间隔、关注哪些字段。
//
// 为什么要抽这一层
// ---------------
// 换游戏 = 换一份 profile + 换一张偏移表。框架代码一行不动。
// 这是"框架能被复用"和"只能给一个游戏用"的分界线。
#pragma once

#include <string>
#include <vector>

namespace profile {

struct Profile {
    // ---------- 目标 ----------
    std::string name;             // 人类可读标识，例如 "mygame"
    std::string exe;              // 进程名，例如 "Game.exe"
    std::string module;           // 模块名，留空表示与 exe 相同

    // ---------- 偏移表 ----------
    std::string table;            // 用 schema::Table::game 匹配

    // ---------- 运行时 ----------
    int poll_ms = 500;            // 快照间隔（毫秒）
    int idle_jitter = 120;        // 间隔抖动幅度（±ms）
    std::vector<std::string> watch;   // 只读这些字段；空表示全部

    // ---------- 行为开关 ----------
    bool require_all_fields = false;  // true: 有任何 Unknown 就停工

    bool valid() const noexcept { return !exe.empty(); }
    std::string module_name() const { return module.empty() ? exe : module; }
};

// ---------- 文本格式 ----------
// 与 schema 的格式保持一致的极简风格，一行一条：
//
//   !name      mygame
//   !exe       Game.exe
//   !module    Game.exe
//   !table     mygame
//   !poll      500
//   !jitter    120
//   !strict    0
//
//   # 关注字段（可多行）
//   watch  player.hp
//   watch  player.pos
//
inline std::string serialize(const Profile& p) {
    std::string out;
    out += "# memkit profile\n";
    out += "!name   " + p.name + "\n";
    out += "!exe    " + p.exe + "\n";
    out += "!module " + p.module + "\n";
    out += "!table  " + p.table + "\n";
    out += "!poll   " + std::to_string(p.poll_ms) + "\n";
    out += "!jitter " + std::to_string(p.idle_jitter) + "\n";
    out += "!strict " + std::string(p.require_all_fields ? "1" : "0") + "\n";
    if (!p.watch.empty()) {
        out += "\n";
        for (const auto& w : p.watch) out += "watch  " + w + "\n";
    }
    return out;
}

inline bool parse(const std::string& text, Profile& out) {
    out = Profile{};

    size_t pos = 0;
    while (pos <= text.size()) {
        size_t nl = text.find('\n', pos);
        const std::string line =
            text.substr(pos, (nl == std::string::npos) ? std::string::npos : nl - pos);
        if (nl == std::string::npos) pos = text.size() + 1;
        else pos = nl + 1;

        // 去注释
        std::string work = line;
        const size_t hash = work.find('#');
        if (hash != std::string::npos) work = work.substr(0, hash);

        // 切词
        std::vector<std::string> tok;
        std::string cur;
        for (char c : work) {
            if (c == ' ' || c == '\t' || c == '\r') {
                if (!cur.empty()) { tok.push_back(cur); cur.clear(); }
            } else {
                cur.push_back(c);
            }
        }
        if (!cur.empty()) tok.push_back(cur);
        if (tok.size() < 2) continue;

        const std::string& k = tok[0];
        const std::string& v = tok[1];

        if (k == "!name") out.name = v;
        else if (k == "!exe") out.exe = v;
        else if (k == "!module") out.module = v;
        else if (k == "!table") out.table = v;
        else if (k == "!poll") out.poll_ms = atoi(v.c_str());
        else if (k == "!jitter") out.idle_jitter = atoi(v.c_str());
        else if (k == "!strict") out.require_all_fields = (v == "1");
        else if (k == "watch") out.watch.push_back(v);
    }

    // 基本合法性
    if (out.poll_ms < 20) out.poll_ms = 20;
    if (out.poll_ms > 60000) out.poll_ms = 60000;
    if (out.idle_jitter < 0) out.idle_jitter = 0;
    if (out.idle_jitter > out.poll_ms) out.idle_jitter = out.poll_ms / 2;

    return out.valid();
}

}  // namespace profile