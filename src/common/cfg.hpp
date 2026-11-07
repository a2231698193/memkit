// common/cfg.hpp —— 配置加密（nonce + 流密钥 + 完整性校验）
//
// 威胁模型：磁盘上的配置文件会被以下三种方式利用：
//   1. strings / 十六进制搜索目标进程名、模块名、偏移链
//   2. 版本对比 —— 玩家把配置贴到论坛，官方据此定位特征
//   3. 篡改 —— 让脚本按攻击者意图跑异常高频的操作
//
// 对策：
//   * 主体用 ChaCha20 位流加密（流密码，随机访问友好，无填充）
//   * 密钥不落文件：由「编译期常量种子」+「运行期机器指纹」+「文件内 nonce」三段派生
//   * 文件头存 nonce 与 HMAC-SHA256 截断值，防篡改
//
// 注意：这不是"绝对安全"，只是把配置从「明文可读」提到「需要逆向」
#pragma once

#include <windows.h>
#include <bcrypt.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "common/rnd.hpp"

namespace cfg {

// ---------- 基础：SHA-256 / HMAC（走 CNG，不落静态导入）----------
inline bool sha256(const uint8_t* data, size_t len, uint8_t out[32]) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE h = nullptr;
    bool ok = false;

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) return false;
    if (BCryptCreateHash(alg, &h, nullptr, 0, nullptr, 0, 0) == 0) {
        if (BCryptHashData(h, const_cast<PUCHAR>(data), static_cast<ULONG>(len), 0) == 0 &&
            BCryptFinishHash(h, out, 32, 0) == 0) {
            ok = true;
        }
        BCryptDestroyHash(h);
    }
    BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

inline bool hmac_sha256(const uint8_t* key, size_t keyLen, const uint8_t* data, size_t len,
                        uint8_t out[32]) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE h = nullptr;
    bool ok = false;

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr,
                                    BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0) {
        return false;
    }
    if (BCryptCreateHash(alg, &h, nullptr, 0, const_cast<PUCHAR>(key),
                         static_cast<ULONG>(keyLen), 0) == 0) {
        if (BCryptHashData(h, const_cast<PUCHAR>(data), static_cast<ULONG>(len), 0) == 0 &&
            BCryptFinishHash(h, out, 32, 0) == 0) {
            ok = true;
        }
        BCryptDestroyHash(h);
    }
    BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

// ---------- ChaCha20（RFC 7539）----------
namespace detail {

inline uint32_t rotl32(uint32_t x, int n) noexcept { return (x << n) | (x >> (32 - n)); }

inline void quarter(uint32_t* s, int a, int b, int c, int d) noexcept {
    s[a] += s[b]; s[d] ^= s[a]; s[d] = rotl32(s[d], 16);
    s[c] += s[d]; s[b] ^= s[c]; s[b] = rotl32(s[b], 12);
    s[a] += s[b]; s[d] ^= s[a]; s[d] = rotl32(s[d], 8);
    s[c] += s[d]; s[b] ^= s[c]; s[b] = rotl32(s[b], 7);
}

inline void block(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter,
                  uint8_t out[64]) noexcept {
    static const uint32_t kSigma[4] = {0x61707865u, 0x3320646Eu, 0x79622D32u, 0x6B206574u};
    uint32_t s[16];
    uint32_t w[16];

    s[0] = kSigma[0]; s[1] = kSigma[1]; s[2] = kSigma[2]; s[3] = kSigma[3];
    for (int i = 0; i < 8; ++i) {
        std::memcpy(&s[4 + i], key + 4 * i, 4);
    }
    s[12] = counter;
    std::memcpy(&s[13], nonce + 0, 4);
    std::memcpy(&s[14], nonce + 4, 4);
    std::memcpy(&s[15], nonce + 8, 4);

    std::memcpy(w, s, sizeof(s));
    for (int round = 0; round < 10; ++round) {
        quarter(w, 0, 4, 8, 12);
        quarter(w, 1, 5, 9, 13);
        quarter(w, 2, 6, 10, 14);
        quarter(w, 3, 7, 11, 15);
        quarter(w, 0, 5, 10, 15);
        quarter(w, 1, 6, 11, 12);
        quarter(w, 2, 7, 8, 13);
        quarter(w, 3, 4, 9, 14);
    }
    for (int i = 0; i < 16; ++i) {
        const uint32_t v = w[i] + s[i];
        std::memcpy(out + 4 * i, &v, 4);
    }
}

inline void xor_stream(const uint8_t key[32], const uint8_t nonce[12], uint8_t* data,
                       size_t len) noexcept {
    uint8_t ks[64];
    uint32_t counter = 0;
    size_t off = 0;
    while (off < len) {
        block(key, nonce, counter++, ks);
        const size_t n = (len - off) < 64 ? (len - off) : 64;
        for (size_t i = 0; i < n; ++i) data[off + i] ^= ks[i];
        off += n;
    }
}

}  // namespace detail

// ---------- 机器指纹：参与密钥派生，配置换机不解 ----------
struct Fingerprint {
    uint64_t volume_serial = 0;
    uint64_t computer_hash = 0;
    uint64_t user_hash = 0;

    uint8_t digest[32]{};
};

inline Fingerprint fingerprint() {
    Fingerprint f;

    // 卷序列号（系统盘）
    wchar_t sys[MAX_PATH]{};
    if (GetSystemWindowsDirectoryW(sys, MAX_PATH)) {
        wchar_t root[8] = {sys[0], L':', L'\\', 0};
        DWORD serial = 0;
        if (GetVolumeInformationW(root, nullptr, 0, &serial, nullptr, nullptr, nullptr, 0)) {
            f.volume_serial = serial;
        }
    }

    // 计算机名 + 用户名 → 各自哈希（不落盘，只参与派生）
    wchar_t buf[256]{};
    DWORD n = 256;
    if (GetComputerNameW(buf, &n)) {
        uint32_t h = 2166136261u;
        for (DWORD i = 0; i < n; ++i) {
            h ^= static_cast<uint8_t>(buf[i] & 0xFF);
            h *= 16777619u;
        }
        f.computer_hash = h;
    }
    // 用户区分改用 %USERPROFILE% 路径：kernel32 的 GetEnvironmentVariableW 即可，
    // 避免为 GetUserNameW 引入 advapi32 依赖（每多一个 DLL 就多一分特征）
    n = GetEnvironmentVariableW(L"USERPROFILE", buf, 256);
    if (n > 0 && n < 256) {
        uint32_t h = 2166136261u;
        for (DWORD i = 0; i < n; ++i) {
            h ^= static_cast<uint8_t>(buf[i] & 0xFF);
            h *= 16777619u;
        }
        f.user_hash = h;
    }

    // 三段拼一起再 sha256，作为最终指纹
    uint8_t raw[24];
    std::memcpy(raw + 0, &f.volume_serial, 8);
    std::memcpy(raw + 8, &f.computer_hash, 8);
    std::memcpy(raw + 16, &f.user_hash, 8);
    sha256(raw, sizeof(raw), f.digest);
    return f;
}

// ---------- 容器格式 ----------
#pragma pack(push, 1)
struct Header {
    uint32_t magic = 0x31474643u;  // "CFG1"
    uint16_t version = 1;
    uint16_t flags = 0;
    uint8_t nonce[12]{};
    uint8_t mac[16]{};             // HMAC-SHA256 截断 16 字节
    uint32_t plain_len = 0;
    uint32_t crc = 0;              // 明文 CRC32，快速判错
};
#pragma pack(pop)

inline constexpr size_t kHeaderSize = sizeof(Header);

// 密钥派生：编译期种子 ⊕ 指纹 ⊕ nonce，再 SHA-256
inline void derive_key(uint32_t seed, const Fingerprint& fp, const uint8_t nonce[12],
                       uint8_t outKey[32]) {
    uint8_t raw[4 + 32 + 12];
    std::memcpy(raw + 0, &seed, 4);
    std::memcpy(raw + 4, fp.digest, 32);
    std::memcpy(raw + 36, nonce, 12);
    sha256(raw, sizeof(raw), outKey);
}

inline uint32_t crc32(const uint8_t* p, size_t n) noexcept {
    static uint32_t table[256];
    static bool ready = false;
    if (!ready) {
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int k = 0; k < 8; ++k) c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            table[i] = c;
        }
        ready = true;
    }
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; ++i) c = table[(c ^ p[i]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

// ---------- 加解密 ----------
inline std::vector<uint8_t> seal(const std::string& plain, uint32_t seed) {
    std::vector<uint8_t> out;
    const Fingerprint fp = fingerprint();

    Header hd;
    const uint64_t r = rnd::sys64();
    std::memcpy(hd.nonce, &r, 8);
    std::memcpy(hd.nonce + 8, &seed, 4);
    hd.plain_len = static_cast<uint32_t>(plain.size());
    hd.crc = crc32(reinterpret_cast<const uint8_t*>(plain.data()), plain.size());

    uint8_t key[32];
    derive_key(seed, fp, hd.nonce, key);

    out.resize(kHeaderSize + plain.size());
    std::memcpy(out.data(), &hd, kHeaderSize);
    if (!plain.empty()) {
        std::memcpy(out.data() + kHeaderSize, plain.data(), plain.size());
        detail::xor_stream(key, hd.nonce, out.data() + kHeaderSize, plain.size());
    }

    uint8_t mac[32];
    if (hmac_sha256(key, sizeof(key), out.data() + kHeaderSize, plain.size(), mac)) {
        std::memcpy(out.data() + offsetof(Header, mac), mac, 16);
    }

    // 清零栈上密钥
    SecureZeroMemory(key, sizeof(key));
    return out;
}

inline bool open(const std::vector<uint8_t>& blob, uint32_t seed, std::string& plain) {
    if (blob.size() < kHeaderSize) return false;

    Header hd;
    std::memcpy(&hd, blob.data(), kHeaderSize);
    if (hd.magic != 0x31474643u || hd.version != 1) return false;
    if (blob.size() != kHeaderSize + hd.plain_len) return false;

    const Fingerprint fp = fingerprint();
    uint8_t key[32];
    derive_key(seed, fp, hd.nonce, key);

    // 先验 MAC 再解密：拒绝篡改的 blob，避免解密出垃圾仍被业务使用
    uint8_t mac[32];
    if (!hmac_sha256(key, sizeof(key), blob.data() + kHeaderSize, hd.plain_len, mac)) {
        SecureZeroMemory(key, sizeof(key));
        return false;
    }
    uint8_t cropped[16];
    std::memcpy(cropped, offsetof(Header, mac) + blob.data(), 16);
    if (std::memcmp(mac, cropped, 16) != 0) {
        SecureZeroMemory(key, sizeof(key));
        return false;
    }

    plain.assign(reinterpret_cast<const char*>(blob.data() + kHeaderSize), hd.plain_len);
    detail::xor_stream(key, hd.nonce, reinterpret_cast<uint8_t*>(&plain[0]), plain.size());

    SecureZeroMemory(key, sizeof(key));

    if (crc32(reinterpret_cast<const uint8_t*>(plain.data()), plain.size()) != hd.crc) {
        plain.clear();
        return false;
    }
    return true;
}

}  // namespace cfg
