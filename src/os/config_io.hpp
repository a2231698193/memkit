// os/config_io.hpp —— 偏移表 / 配置的磁盘读写（加密）
//
// 为什么单独一层
// -------------
// 磁盘 I/O 是最容易留下痕迹的地方。这个文件把三件事封在一起，
// 保证业务代码不会绕过它们直接 open/read：
//
//   1. **文件名随机化**：不叫 "offsets.txt"，叫 <随机 12 字符>.dat
//   2. **内容加密**：走 cfg 层的 ChaCha20 + HMAC
//   3. **不留副产物**：不写 .tmp / .bak，写入用覆盖模式
//
// 目录选择
// --------
// 不放在程序目录（可预测），放在 %LOCALAPPDATA%\<随机目录名>\ 下。
// 随机目录名在首次运行时生成，存进注册表（HKCU，不需要管理员）。
#pragma once

#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

#include "common/cfg.hpp"
#include "os/schema.hpp"

namespace cfgio {

// 编译期种子：与 cfg::seal 的 seed 共同决定密钥
inline constexpr uint32_t kTableSeed = 0x7B4D2F19u;
inline constexpr uint32_t kRegSeed = 0x3E8A1C55u;
inline constexpr uint32_t kProfileSeed = 0x2D71A9F3u;

// ---------- 路径管理 ----------
class Paths {
public:
    // 首次调用时生成随机目录名并存注册表；之后复用
    bool init() noexcept {
        if (ready_) return true;

        // 1. 读注册表里已有的随机目录名
        if (read_dir_name()) {
            ready_ = true;
            return true;
        }

        // 2. 没有就生成一个
        if (!write_dir_name()) return false;
        ready_ = true;
        return true;
    }

    // 完整的表文件路径
    std::wstring table_path(const std::wstring& name = L"t") const {
        std::wstring p = dir_;
        if (!p.empty() && p.back() != L'\\') p.push_back(L'\\');
        p += name;
        p += L".dat";
        return p;
    }

    // profile 文件路径（固定名，与表分开）
    std::wstring profile_path() const {
        std::wstring p = dir_;
        if (!p.empty() && p.back() != L'\\') p.push_back(L'\\');
        p += L"p.dat";
        return p;
    }

    const std::wstring& dir() const noexcept { return dir_; }

private:
    bool read_dir_name() noexcept {
        wchar_t buf[64] = {};
        DWORD type = 0, bytes = sizeof(buf) - sizeof(wchar_t);

        HKEY key = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Classes\\CLSID", 0,
                          KEY_READ, &key) != ERROR_SUCCESS) {
            return false;
        }
        // 用一个不显眼的子键（伪装成 COM 注册项的一部分）
        RegCloseKey(key);

        if (RegOpenKeyExW(HKEY_CURRENT_USER,
                          L"Software\\Classes\\CLSID\\{00000000-0000-0000-0000-000000000000}\\InprocServer32",
                          0, KEY_READ, &key) != ERROR_SUCCESS) {
            return false;
        }
        const LONG rc = RegQueryValueExW(key, L"ThreadingModel", nullptr, &type,
                                         reinterpret_cast<LPBYTE>(buf), &bytes);
        RegCloseKey(key);
        if (rc != ERROR_SUCCESS || type != REG_SZ) return false;

        build_dir(buf);
        return !dir_.empty();
    }

    bool write_dir_name() noexcept {
        // 生成 12 位小写字母数字
        wchar_t token[16] = {};
        static const wchar_t kAlphabet[] = L"abcdefghijklmnopqrstuvwxyz0123456789";
        uint64_t seed = GetTickCount64() ^ (static_cast<uint64_t>(GetCurrentProcessId()) << 32);

        for (int i = 0; i < 12; ++i) {
            seed = seed * 6364136223846793005ull + 1442695040888963407ull;
            token[i] = kAlphabet[(seed >> 33) % 36];
        }
        token[12] = 0;

        HKEY key = nullptr;
        if (RegCreateKeyExW(HKEY_CURRENT_USER,
                            L"Software\\Classes\\CLSID\\{00000000-0000-0000-0000-000000000000}\\InprocServer32",
                            0, nullptr, 0, KEY_WRITE, nullptr, &key, nullptr) != ERROR_SUCCESS) {
            return false;
        }
        const LONG rc = RegSetValueExW(key, L"ThreadingModel", 0, REG_SZ,
                                       reinterpret_cast<const BYTE*>(token),
                                       static_cast<DWORD>((wcslen(token) + 1) * sizeof(wchar_t)));
        RegCloseKey(key);
        if (rc != ERROR_SUCCESS) return false;

        build_dir(token);
        return !dir_.empty();
    }

    void build_dir(const wchar_t* name) {
        wchar_t base[MAX_PATH] = {};
        DWORD n = GetEnvironmentVariableW(L"LOCALAPPDATA", base, MAX_PATH);
        if (n == 0 || n >= MAX_PATH) return;

        dir_ = base;
        if (!dir_.empty() && dir_.back() != L'\\') dir_.push_back(L'\\');
        dir_ += name;
    }

    std::wstring dir_;
    bool ready_ = false;
};

// ---------- 写 ----------
// 先写到内存，再一次性覆盖写盘。避免"写一半崩溃留下残file"。
inline bool write_encrypted(const std::wstring& path, const std::string& plain,
                            uint32_t seed) {
    const auto blob = cfg::seal(plain, seed);
    if (blob.empty()) return false;

    // CREATE_ALWAYS 会截断已有文件，不留 .bak
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        // 目录可能不存在，建一次再试
        const size_t slash = path.find_last_of(L'\\');
        if (slash != std::wstring::npos) {
            CreateDirectoryW(path.substr(0, slash).c_str(), nullptr);
            h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL, nullptr);
        }
        if (h == INVALID_HANDLE_VALUE) return false;
    }

    DWORD wrote = 0;
    const BOOL ok = WriteFile(h, blob.data(), static_cast<DWORD>(blob.size()), &wrote, nullptr);
    CloseHandle(h);
    return ok && wrote == blob.size();
}

// ---------- 读 ----------
inline bool read_encrypted(const std::wstring& path, uint32_t seed, std::string& plain) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart <= 0 || sz.QuadPart > (16 << 20)) {
        CloseHandle(h);
        return false;
    }

    std::vector<uint8_t> blob(static_cast<size_t>(sz.QuadPart));
    DWORD got = 0;
    const BOOL ok = ReadFile(h, blob.data(), static_cast<DWORD>(blob.size()), &got, nullptr);
    CloseHandle(h);
    if (!ok || got != blob.size()) return false;

    return cfg::open(blob, seed, plain);
}

// ---------- 便捷：直接存取 schema::Table ----------
inline bool save_table(const Paths& paths, const schema::Table& t,
                       const std::wstring& name = L"t") {
    const std::string text = schema::serialize(t);
    if (text.empty()) return false;
    return write_encrypted(paths.table_path(name), text, kTableSeed);
}

inline bool load_table(const Paths& paths, schema::Table& out,
                       const std::wstring& name = L"t") {
    std::string text;
    if (!read_encrypted(paths.table_path(name), kTableSeed, text)) return false;
    return schema::parse(text, out);
}

// 批量加载：目录下所有 .dat 都试一遍，成功的加进 registry
inline size_t load_all(const Paths& paths, schema::Registry& reg) {
    std::wstring pattern = paths.dir();
    if (pattern.empty()) return 0;
    if (pattern.back() != L'\\') pattern.push_back(L'\\');
    pattern += L"*.dat";

    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;

    size_t count = 0;
    do {
        std::wstring full = paths.dir();
        if (full.back() != L'\\') full.push_back(L'\\');
        full += fd.cFileName;

        std::string text;
        if (!read_encrypted(full, kTableSeed, text)) continue;

        schema::Table t;
        if (schema::parse(text, t) && !t.fields.empty()) {
            reg.add(std::move(t));
            ++count;
        }
    } while (FindNextFileW(h, &fd));

    FindClose(h);
    return count;
}

}  // namespace cfgio
