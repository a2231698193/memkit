// os/scanpattern.hpp — AOB 特征码扫描（通用层，与具体游戏无关）
//
// 这是"不用调试器也能找到偏移"的核心技术。
//
// 适用面
// ------
// 任何 ×86-64 的原生程序都适用，不限于某个游戏。因为原理是
// "代码里的 RIP 相对寻址指令引用了数据地址"，这是编译器产物，
// 而不是游戏特有的东西。
//
// 原理
// ----
// 游戏每次更新后，数据地址会变（ASLR + 编译差异），但**代码不会大变**。
// 而访问数据的代码里，有一条固定的相对寻址指令：
//
//   48 8B 05 ?? ?? ?? ??    mov rax, [rip+disp32]
//   ^^^^^^^^^^^ 固定         ^^^^^^^^^^^^^^ 这个 disp 就是"数据 - 指令末尾"
//
// 所以只要在代码段里搜这 3 个固定字节，拿到 disp，加上指令末尾地址，
// 就得到数据地址。整个过程不需要人眼，不需要断点，程序自己算。
//
// 特征码（pattern）
// ----------------
// 用十六进制字节串描述，`??` 表示通配：
//
//   "48 8B 05 ?? ?? ?? ?? 33 DB 45 8B E1"
//
// 通配位置正好是要提取的 disp32。这是设计，不是巧合 —— 特征码模板里
// 的通配符同时标出了"要读取的字段"。
//
// 为什么比人工找稳
// --------------
//   * 人工找：看到一条指令 → 记下 disp → 下次更新还是这条指令但 disp 变了
//             → 必须重新找
//   * 扫描：  指令字节没变 → 扫到的位置没变 → 重新算 disp → 自动得到新地址
//
// 只有"指令本身被重编译改掉"时才需要更新特征码。这比更新偏移少得多。
#pragma once

#include <windows.h>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "os/process.hpp"

namespace scan {

// ---------- 特征码解析 ----------
// "48 8B 05 ?? ?? ?? ??" → bytes + mask
struct Pattern {
    std::vector<uint8_t> bytes;
    std::vector<bool> mask;       // true = 需要匹配，false = 通配

    bool valid() const noexcept {
        return !bytes.empty() && bytes.size() == mask.size();
    }

    size_t size() const noexcept { return bytes.size(); }

    // 第一个通配符的位置（-1 表示没有通配）
    int first_wildcard() const noexcept {
        for (size_t i = 0; i < mask.size(); ++i) {
            if (!mask[i]) return static_cast<int>(i);
        }
        return -1;
    }
};

// 解析 "48 8B 05 ?? ?? ?? ??" 或 "488B05?????? ??"
// 容忍空格、大小写、0x 前缀
inline bool parse_pattern(const std::string& text, Pattern& out) {
    out.bytes.clear();
    out.mask.clear();

    size_t i = 0;
    while (i < text.size()) {
        // 跳过空白
        while (i < text.size() && (text[i] == ' ' || text[i] == '\t')) ++i;
        if (i >= text.size()) break;

        // 跳过 0x 前缀
        if (text[i] == '0' && i + 1 < text.size() && (text[i + 1] == 'x' || text[i + 1] == 'X')) {
            i += 2;
        }

        // 通配符：'?' 或 '??' 都表示**一个**字节的通配
        //
        // 这是最容易写错的地方。约定是：
        //   "??"  = 一个通配字节（IDA / x64dbg / SigScan 库的通用写法）
        //   "?"   = 同上，容错
        //   "????" = 四个通配字节（紧凑写法，4 个 '?' 逐个计）
        //
        // 所以逻辑是：吃掉 1 或 2 个 '?'，只产生 1 个通配字节。
        // 之前写成"每个 ? 都产生一个字节"，导致 "?? ?? ?? ??" 变成 8 字节
        // 而不是 4 字节，整个模式错位。
        if (text[i] == '?') {
            out.bytes.push_back(0);
            out.mask.push_back(false);
            ++i;
            // 第二个 '?' 作为同一个通配的一部分吃掉
            if (i < text.size() && text[i] == '?') ++i;
            continue;
        }

        // 十六进制字节（1 或 2 位）
        auto nibble = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };

        const int hi = nibble(text[i]);
        if (hi < 0) return false;

        int value = hi;
        ++i;
        if (i < text.size()) {
            const int lo = nibble(text[i]);
            if (lo >= 0) {
                value = (hi << 4) | lo;
                ++i;
            }
        }

        out.bytes.push_back(static_cast<uint8_t>(value));
        out.mask.push_back(true);
    }

    // 至少要有一个固定字节，否则这个模式没有意义
    bool hasFixed = false;
    for (bool m : out.mask) {
        if (m) { hasFixed = true; break; }
    }
    return out.valid() && hasFixed;
}

// ---------- 扫描结果 ----------
struct Hit {
    uintptr_t addr = 0;      // 匹配起始地址
    bool ok = false;
};

// 在 [start, start+size) 范围内扫第一个匹配
// 分块读，避免一次读几百 MB
inline Hit find_first(os::Session& s, uintptr_t start, size_t size, const Pattern& p,
                      size_t chunkSize = 1 << 20) {
    Hit hit;
    if (!p.valid() || size < p.size()) return hit;

    std::vector<uint8_t> buf(chunkSize + p.size());
    const size_t overlap = p.size() - 1;   // 防止跨块的匹配被漏掉

    for (size_t off = 0; off < size; off += chunkSize) {
        const size_t want = (size - off) < chunkSize ? (size - off) : chunkSize;
        const size_t readLen = (want + overlap) < buf.size() ? (want + overlap) : buf.size();

        // 逐块读；失败时**缩小到单页重试**，而不是整块跳过。
        //
        // 之前整块跳过导致：模块尾部那块跨到了不可读页，
        // 于是整块（1MB）都没被扫描，表现为"扫描 0 命中"。
        size_t got = 0;
        if (s.Read(start + off, buf.data(), readLen)) {
            got = readLen;
        } else {
            // 退化成 4KB 粒度，能读到多少算多少
            constexpr size_t kPage = 0x1000;
            for (size_t sub = 0; sub < readLen; sub += kPage) {
                const size_t n = (readLen - sub) < kPage ? (readLen - sub) : kPage;
                if (!s.Read(start + off + sub, buf.data() + sub, n)) break;
                got = sub + n;
            }
        }
        if (got < p.size()) continue;

        // 只在 [0, want) 范围内找起点，避免重复匹配重叠区
        const size_t limit = got < (want + overlap) ? got : (want + overlap);
        const size_t searchEnd = (limit >= p.size()) ? (limit - p.size()) : 0;
        const size_t startEnd = want < (searchEnd + 1) ? want : (searchEnd + 1);

        for (size_t i = 0; i < startEnd; ++i) {
            bool match = true;
            for (size_t j = 0; j < p.size(); ++j) {
                if (p.mask[j] && buf[i + j] != p.bytes[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                hit.addr = start + off + i;
                hit.ok = true;
                return hit;
            }
        }
    }

    return hit;
}

// 扫全部匹配（用于判断特征码是否唯一 —— 不唯一的特征码不可用）
inline std::vector<uintptr_t> find_all(os::Session& s, uintptr_t start, size_t size,
                                       const Pattern& p, size_t maxHits = 16,
                                       size_t chunkSize = 1 << 20) {
    std::vector<uintptr_t> out;
    if (!p.valid() || size < p.size()) return out;

    std::vector<uint8_t> buf(chunkSize + p.size());
    const size_t overlap = p.size() - 1;

    for (size_t off = 0; off < size; off += chunkSize) {
        const size_t want = (size - off) < chunkSize ? (size - off) : chunkSize;
        const size_t readLen = (want + overlap) < buf.size() ? (want + overlap) : buf.size();

        size_t got = 0;
        if (s.Read(start + off, buf.data(), readLen)) {
            got = readLen;
        } else {
            constexpr size_t kPage = 0x1000;
            for (size_t sub = 0; sub < readLen; sub += kPage) {
                const size_t n = (readLen - sub) < kPage ? (readLen - sub) : kPage;
                if (!s.Read(start + off + sub, buf.data() + sub, n)) break;
                got = sub + n;
            }
        }
        if (got < p.size()) continue;

        const size_t limit = got < (want + overlap) ? got : (want + overlap);
        const size_t searchEnd = (limit >= p.size()) ? (limit - p.size()) : 0;
        const size_t startEnd = want < (searchEnd + 1) ? want : (searchEnd + 1);

        for (size_t i = 0; i < startEnd; ++i) {
            bool match = true;
            for (size_t j = 0; j < p.size(); ++j) {
                if (p.mask[j] && buf[i + j] != p.bytes[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                out.push_back(start + off + i);
                if (out.size() >= maxHits) return out;
            }
        }
    }
    return out;
}

// ---------- 解析 RIP 相对寻址 ----------
//
// 从命中位置 + 通配位置 提取 disp32，算出目标地址。
//
//   48 8B 05 [disp32]       mov rax, [rip+disp32]
//   ^命中    ^通配起点
//
// rip 指向**下一条指令**，所以：
//   目标 = 命中地址 + 通配位置 + 4 + disp32
//        = 命中地址 + 指令长度 + disp32
//
// 参数 wildcardOffset 是"通配符相对命中起点的字节偏移"。
// 对上面这条指令，通配在 index 3，指令总长 7。
inline uintptr_t resolve_rip_relative(os::Session& s, uintptr_t hitAddr,
                                      size_t wildcardOffset, size_t wildcardLen = 4) {
    int32_t disp = 0;
    if (!s.Read(hitAddr + wildcardOffset, disp)) return 0;

    const uintptr_t nextInsn = hitAddr + wildcardOffset + wildcardLen;
    return static_cast<uintptr_t>(static_cast<int64_t>(nextInsn) + disp);
}

// 变体：直接读目标位置里的绝对指针
//   48 8B 05 [disp32]   → 目标地址里存的是指针
// 常用于"模块内静态变量，值是指向堆的指针"
inline uintptr_t resolve_rip_then_deref(os::Session& s, uintptr_t hitAddr,
                                        size_t wildcardOffset, size_t wildcardLen = 4) {
    const uintptr_t slot = resolve_rip_relative(s, hitAddr, wildcardOffset, wildcardLen);
    if (slot == 0) return 0;
    uintptr_t value = 0;
    if (!s.Read(slot, value)) return 0;
    return value;
}

// ---------- 高层封装：一步到位 ----------
struct ResolveResult {
    bool ok = false;
    uintptr_t hit = 0;      // 特征码命中位置
    uintptr_t target = 0;   // 解析出的数据地址
    int matches = 0;        // 命中次数（>1 说明特征码不唯一）
};

// 用法：
//   scan::ResolveResult r = scan::resolve(session, modBase, modSize,
//         "48 8B 05 ?? ?? ?? ?? 33 DB 45 8B E1");
//   if (r.ok) { /* r.target 就是偏移 */ }
inline ResolveResult resolve(os::Session& s, uintptr_t moduleBase, size_t moduleSize,
                             const std::string& patternText, bool deref = false,
                             int64_t addend = 0) {
    ResolveResult r;

    Pattern p;
    if (!parse_pattern(patternText, p)) return r;

    const auto hits = find_all(s, moduleBase, moduleSize, p, 2);
    r.matches = static_cast<int>(hits.size());
    if (hits.empty()) return r;

    // 命中多个 = 特征码不唯一，结果不可信。
    // 这是最重要的判据：不唯一的特征码在版本更新后会随机命中不同位置，
    // 比找不到更危险 —— 找不到会报错，找错会静默用错数据。
    if (hits.size() > 1) return r;

    r.hit = hits[0];

    // 没有通配 = 纯定位模式（比如找 PE 头、找某段固定指令）。
    // 这种模式不需要解析 disp，命中地址本身就是结果。
    const int wc = p.first_wildcard();
    if (wc < 0) {
        r.target = r.hit;
        r.ok = true;
        return r;
    }

    // 通配段长度：从第一个通配到下一个固定字节之前
    size_t wcLen = 0;
    for (size_t i = static_cast<size_t>(wc); i < p.size(); ++i) {
        if (p.mask[i]) break;
        ++wcLen;
    }
    // 只有 disp32 这一种情况，其他长度不处理
    if (wcLen != 4) return r;

    const uintptr_t base = deref ? resolve_rip_then_deref(s, r.hit, static_cast<size_t>(wc), 4)
                                 : resolve_rip_relative(s, r.hit, static_cast<size_t>(wc), 4);
    if (base == 0) return r;

    r.target = static_cast<uintptr_t>(static_cast<int64_t>(base) + addend);
    r.ok = true;
    return r;
}

}  // namespace scan
