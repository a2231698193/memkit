// ipc/channel.hpp —— 控制端/被控端之间的帧协议（随机名管道）
//
// P2 补全：双向收发、请求-响应配对、超时丢弃、粘包/半包处理
//
// 帧格式（全部小端）：
//   0  u32 magic   CHAN
//   4  u16 op      操作码
//   6  u16 seq     请求序号（响应必须回填同值）
//   8  u16 len     payload 长度
//  10  u16 flags   0=请求 1=响应 2=错误
//  12  u32 crc     payload 的 CRC32
//  16  payload
#pragma once

#include <windows.h>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "stealth/ident.hpp"

namespace ipc {

inline constexpr uint32_t kMagic = 0x4E414843u;  // "CHAN"
inline constexpr uint16_t kMaxPayload = 4080;
inline constexpr size_t kHeaderSize = 16;

enum Flags : uint16_t {
    kReq = 0,
    kResp = 1,
    kErr = 2,
};

// 操作码：P2 只有控制面，不承载业务
enum Op : uint16_t {
    kOpPing = 1,
    kOpInfo = 2,
    kOpLogSnapshot = 3,
    kOpStats = 4,
    kOpShutdown = 5,
};

#pragma pack(push, 1)
struct Header {
    uint32_t magic;
    uint16_t op;
    uint16_t seq;
    uint16_t len;
    uint16_t flags;
    uint32_t crc;
};
#pragma pack(pop)

static_assert(sizeof(Header) == kHeaderSize, "header layout mismatch");

inline uint32_t crc32(const uint8_t* p, size_t n) noexcept {
    static uint32_t table[256];
    static bool init = false;
    if (!init) {
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int k = 0; k < 8; ++k) c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            table[i] = c;
        }
        init = true;
    }
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; ++i) c = table[(c ^ p[i]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

struct Frame {
    uint16_t op = 0;
    uint16_t seq = 0;
    uint16_t flags = kReq;
    std::vector<uint8_t> payload;
};

// ---------- 端点基类：收发与组帧解帧 ----------
class Endpoint {
public:
    virtual ~Endpoint() { close(); }

    bool opened() const noexcept { return h_ != nullptr && h_ != INVALID_HANDLE_VALUE; }

    bool send(const Frame& f) noexcept {
        if (!opened() || f.payload.size() > kMaxPayload) return false;

        Header hd{};
        hd.magic = kMagic;
        hd.op = f.op;
        hd.seq = f.seq;
        hd.len = static_cast<uint16_t>(f.payload.size());
        hd.flags = f.flags;
        hd.crc = crc32(f.payload.data(), f.payload.size());

        // 单次 WriteFile 把头和体一起写出去，避免两次写入被对端当成两帧
        std::vector<uint8_t> buf(kHeaderSize + f.payload.size());
        std::memcpy(buf.data(), &hd, kHeaderSize);
        if (!f.payload.empty()) {
            std::memcpy(buf.data() + kHeaderSize, f.payload.data(), f.payload.size());
        }

        DWORD wrote = 0;
        const BOOL ok = WriteFile(h_, buf.data(), static_cast<DWORD>(buf.size()), &wrote, nullptr);
        return ok && wrote == buf.size();
    }

    // 非阻塞尝试收一帧；返回 false 表示"暂无完整帧"（不是错误）
    bool try_recv(Frame& out) noexcept {
        if (!opened()) return false;

        // 先把内核缓冲里的字节全部吸进 rx_，解决半包
        for (;;) {
            uint8_t tmp[1024];
            DWORD got = 0;
            if (!ReadFile(h_, tmp, sizeof(tmp), &got, nullptr) || got == 0) break;
            rx_.insert(rx_.end(), tmp, tmp + got);
            if (rx_.size() > kHeaderSize + kMaxPayload * 4) {
                rx_.clear();  // 对端异常，丢弃积压
                return false;
            }
        }

        if (rx_.size() < kHeaderSize) return false;

        Header hd;
        std::memcpy(&hd, rx_.data(), kHeaderSize);
        if (hd.magic != kMagic || hd.len > kMaxPayload) {
            // 帧头坏了：整体丢弃，宁可丢消息也不做"猜测式"重同步
            rx_.clear();
            return false;
        }
        if (rx_.size() < kHeaderSize + hd.len) return false;  // 半包，等下一次

        out.op = hd.op;
        out.seq = hd.seq;
        out.flags = hd.flags;
        out.payload.assign(rx_.begin() + kHeaderSize, rx_.begin() + kHeaderSize + hd.len);

        // CRC 不对就丢，不信任的帧绝不进业务层
        if (crc32(out.payload.data(), out.payload.size()) != hd.crc) {
            rx_.erase(rx_.begin(), rx_.begin() + kHeaderSize + hd.len);
            return false;
        }

        rx_.erase(rx_.begin(), rx_.begin() + kHeaderSize + hd.len);
        return true;
    }

    void close() noexcept {
        if (opened()) CloseHandle(h_);
        h_ = nullptr;
        rx_.clear();
    }

protected:
    HANDLE h_ = nullptr;
    std::vector<uint8_t> rx_;
};

// ---------- 服务端（被控端）----------
class Server final : public Endpoint {
public:
    bool open() {
        name_ = ident::pipe_name();
        // 非阻塞 + 单实例：MAX_INSTANCES=1，避免被多次连接形成特征
        h_ = CreateNamedPipeW(name_.c_str(), PIPE_ACCESS_DUPLEX,
                              PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT, 1, 16384, 16384,
                              0, nullptr);
        return opened();
    }

    const std::wstring& name() const noexcept { return name_; }

    bool connected() const noexcept { return connected_; }

    // 非阻塞接受连接
    bool accept_pending() noexcept {
        if (!opened() || connected_) return connected_;
        if (ConnectNamedPipe(h_, nullptr)) {
            connected_ = true;
        } else {
            const DWORD e = GetLastError();
            if (e == ERROR_PIPE_CONNECTED) connected_ = true;
        }
        return connected_;
    }

    // 断线后重建管道，保持服务可用
    bool reset_pipe() noexcept {
        close();
        connected_ = false;
        return open();
    }

private:
    std::wstring name_;
    bool connected_ = false;
};

// ---------- 客户端（控制端）----------
class Client final : public Endpoint {
public:
    bool connect(const std::wstring& name, DWORD timeoutMs = 300) {
        for (;;) {
            h_ = CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                             0, nullptr);
            if (opened()) {
                // 切到非阻塞读，与服务端一致
                DWORD mode = PIPE_READMODE_BYTE | PIPE_NOWAIT;
                SetNamedPipeHandleState(h_, &mode, nullptr, nullptr);
                return true;
            }
            if (timeoutMs == 0) return false;
            const DWORD step = timeoutMs > 20 ? 20 : timeoutMs;
            Sleep(step);
            timeoutMs -= step;
        }
    }
};

}  // namespace ipc
