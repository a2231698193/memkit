// input/driver_stub.hpp —— 驱动输入后端占位（P2）
// 目标：输入链路上不出现 LLMHF_INJECTED，且不依赖 SendInput/SendMessage 系列
// MVP 阶段一律返回 false，保证框架默认不会走"可检测路径"
#pragma once

#include "input/backend.hpp"

namespace input {

class DriverBackend final : public IBackend {
public:
    const char* name() const noexcept override { return "driver"; }

    bool init() noexcept override {
        // TODO(P2)：打开设备对象 \Device\<随机名>，校验 IOCTL 版本
        ready_ = false;
        return ready_;
    }

    bool key(uint16_t, bool) noexcept override { return false; }
    bool move_abs(int, int) noexcept override { return false; }

    void shutdown() noexcept override {
        // TODO(P2)：关闭设备句柄、清零上下文
        ready_ = false;
    }

    bool injectable_marker() const noexcept override { return false; }

private:
    bool ready_ = false;
};

}  // namespace input
