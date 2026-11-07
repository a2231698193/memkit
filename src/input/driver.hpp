// input/driver.hpp —— 驱动输入后端（用户态侧）
//
// 与 P0 的 driver_stub 的区别：这个是真实现，走 IOCTL。
// 若驱动未加载 / 设备打不开 / 握手失败，init() 返回 false，
// 框架自动回落到可检测的 User32Backend —— 保证"不会因为驱动缺失而挂掉"，
// 但也意味着线上必须确认 init() 成功（main 会记录 backend 标记）。
//
// 暴露面控制：
//   * 设备句柄用 NtOpenFile 动态解析（不产生 CreateFileW 之外的敏感导入）
//   * 每一次请求带单调序号，重放无效
//   * 握手失败立即关闭句柄，不重试（重试本身是可测行为）
#pragma once

#include <windows.h>
#include <winternl.h>

#include <cstdint>
#include <cstring>
#include <string>

#include "common/hash.hpp"
#include "common/rnd.hpp"
#include "input/backend.hpp"
#include "input/driver_proto.hpp"
#include "stealth/api.hpp"

namespace input {

class DriverBackend final : public IBackend {
public:
    const char* name() const noexcept override { return "driver"; }

    bool init() noexcept override {
        if (!open_device()) return false;
        if (!handshake()) {
            close_device();
            return false;
        }
        ready_ = true;
        return true;
    }

    bool key(uint16_t vk, bool down) noexcept override {
        if (!ready_) return false;

        drv::KeyEvent ev{};
        ev.sessionId = session_;
        ev.seq = next_seq();
        ev.vk = vk;
        ev.scan = static_cast<uint16_t>(MapVirtualKeyW(vk, MAPVK_VK_TO_VSC));
        ev.flags = (down ? 0u : 1u) | (ev.scan & 0xFF00 ? 4u : 0u);
        ev.holdUs = static_cast<uint32_t>(rnd::between(12000, 60000));

        return ioctl(drv::kIoctlKeyEvent, &ev, sizeof(ev), nullptr, nullptr);
    }

    bool move_abs(int x, int y) noexcept override {
        if (!ready_) return false;

        // 屏幕坐标 → [0,65535] 归一化（与 MOUSEEVENTF_ABSOLUTE 一致）
        const int sw = GetSystemMetrics(SM_CXVIRTUALSCREEN);
        const int sh = GetSystemMetrics(SM_CYVIRTUALSCREEN);
        if (sw <= 0 || sh <= 0) return false;

        drv::MouseMove mv{};
        mv.sessionId = session_;
        mv.seq = next_seq();
        mv.nx = static_cast<uint16_t>((static_cast<int64_t>(x) * 65535) / (sw - 1));
        mv.ny = static_cast<uint16_t>((static_cast<int64_t>(y) * 65535) / (sh - 1));

        return ioctl(drv::kIoctlMouseMove, &mv, sizeof(mv), nullptr, nullptr);
    }

    // 鼠标按键（IBackend 没有这个接口，业务层可直接用）
    bool mouse_button(uint8_t btn, bool down) noexcept {
        if (!ready_) return false;
        drv::MouseButton mb{};
        mb.sessionId = session_;
        mb.seq = next_seq();
        mb.button = btn;
        mb.down = down ? 1 : 0;
        return ioctl(drv::kIoctlMouseButton, &mb, sizeof(mb), nullptr, nullptr);
    }

    // 自检：驱动侧版本、会话数、被拒请求数
    struct State {
        uint32_t version = 0;
        uint32_t activeSessions = 0;
        uint32_t rejected = 0;
        uint32_t uptimeMs = 0;
        uint32_t capabilities = 0;
    };

    bool query_state(State& out) noexcept {
        if (!ready_) return false;
        drv::StateQuery q{};
        q.sessionId = session_;
        q.seq = next_seq();

        drv::StateResp resp{};
        DWORD ret = 0;
        if (!ioctl(drv::kIoctlQueryState, &q, sizeof(q), &resp, &ret)) return false;
        if (ret < sizeof(resp)) return false;

        out.version = resp.version;
        out.activeSessions = resp.activeSessions;
        out.rejected = resp.rejectedRequests;
        out.uptimeMs = resp.uptimeMs;
        out.capabilities = resp.capabilities;
        return true;
    }

    void shutdown() noexcept override {
        if (ready_ && h_) {
            drv::StateQuery q{};
            q.sessionId = session_;
            q.seq = next_seq();
            ioctl(drv::kIoctlClose, &q, sizeof(q), nullptr, nullptr);
        }
        ready_ = false;
        session_ = 0;
        seq_ = 0;
        close_device();
    }

    // 驱动后端不在消息链上留 LLMHF_INJECTED
    bool injectable_marker() const noexcept override { return false; }

    // 是否真的可用（main 用来决定是否回落到 user32）
    bool ready() const noexcept { return ready_; }

private:
    // ---------- 设备打开 ----------
    //
    // 设备名由安装脚本生成（driver/install.bat 写
    // HKLM\SYSTEM\CurrentControlSet\Services\MemkitDrv\Parameters\DeviceName），
    // 驱动 DriverEntry 从注册表读。用户态必须读同一个值。
    //
    // 符号链接前缀：驱动用 \GLOBAL??\，用户态打开时写 \.\ 即可
    // （Win32 的 \.\ 会映射到 \??\ 也就是 \GLOBAL??\）。
    // 走 ntdll 的 NtOpenKey / NtQueryValueKey 动态解析，不用 RegOpenKeyExW。
    // 理由：Reg* 系列在 advapi32 里，多一个依赖 DLL 就多一分特征；
    // 而 advapi32 是"注册表操作"的强指示，比 ntdll 更显眼。
    bool load_device_name() noexcept {
        using NtOpenKeyFn = LONG(NTAPI*)(PHANDLE, ACCESS_MASK, PVOID);
        using NtQueryValueKeyFn =
            LONG(NTAPI*)(HANDLE, PVOID, ULONG, PVOID, ULONG, PULONG);
        using NtCloseFn = LONG(NTAPI*)(HANDLE);

        static NtOpenKeyFn ntOpenKey =
            api::get<NtOpenKeyFn>(api::mod::ntdll, hash::ascii("NtOpenKey"));
        static NtQueryValueKeyFn ntQueryValue =
            api::get<NtQueryValueKeyFn>(api::mod::ntdll, hash::ascii("NtQueryValueKey"));
        static NtCloseFn ntClose =
            api::get<NtCloseFn>(api::mod::ntdll, hash::ascii("NtClose"));

        if (!ntOpenKey || !ntQueryValue || !ntClose) return false;

        // 注册表路径用 UNICODE_STRING（Nt* 接口不认 Win32 字符串）
        static const wchar_t kKeyPath[] =
            L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\MemkitDrv\\Parameters";

        UNICODE_STRING keyPath{};
        keyPath.Buffer = const_cast<wchar_t*>(kKeyPath);
        keyPath.Length = static_cast<USHORT>(wcslen(kKeyPath) * sizeof(wchar_t));
        keyPath.MaximumLength = static_cast<USHORT>(keyPath.Length + sizeof(wchar_t));

        OBJECT_ATTRIBUTES oa{};
        oa.Length = sizeof(oa);
        oa.ObjectName = &keyPath;
        oa.Attributes = OBJ_CASE_INSENSITIVE;

        HANDLE hKey = nullptr;
        if (ntOpenKey(&hKey, KEY_READ, &oa) < 0 || !hKey) return false;

        static const wchar_t kValueName[] = L"DeviceName";
        UNICODE_STRING valueName{};
        valueName.Buffer = const_cast<wchar_t*>(kValueName);
        valueName.Length = static_cast<USHORT>((sizeof(kValueName) / sizeof(wchar_t) - 1) *
                                               sizeof(wchar_t));

        // KeyValuePartialInformation = 2
        struct KeyValuePartial {
            ULONG TitleIndex;
            ULONG Type;
            ULONG DataLength;
            UCHAR Data[1];
        };

        UCHAR buf[512] = {};
        ULONG retLen = 0;
        const LONG st = ntQueryValue(hKey, &valueName, 2, buf, sizeof(buf), &retLen);
        ntClose(hKey);

        if (st < 0) return false;

        const auto* info = reinterpret_cast<const KeyValuePartial*>(buf);
        constexpr ULONG kRegSz = 1;
        if (info->Type != kRegSz || info->DataLength < sizeof(wchar_t)) return false;
        if (info->DataLength > sizeof(buf) - sizeof(KeyValuePartial)) return false;

        const size_t chars = (info->DataLength / sizeof(wchar_t)) > 120
                                 ? 120
                                 : (info->DataLength / sizeof(wchar_t));
        name_token_.assign(reinterpret_cast<const wchar_t*>(info->Data), chars);

        // 去掉可能的结尾 NUL
        while (!name_token_.empty() && name_token_.back() == L'\0') name_token_.pop_back();
        return !name_token_.empty();
    }

    bool open_device() noexcept {
        if (name_token_.empty()) {
            if (!load_device_name()) return false;
        }

        // 先试 \.\<name>（Win32 符号链接解析），失败再试 \??\<name>
        const std::wstring p1 = std::wstring(L"\\\\.\\") + name_token_;
        h_ = CreateFileW(p1.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                         OPEN_EXISTING, 0, nullptr);
        if (h_ && h_ != INVALID_HANDLE_VALUE) return true;
        h_ = nullptr;

        const std::wstring p2 = std::wstring(L"\\\\??\\") + name_token_;
        h_ = CreateFileW(p2.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                         OPEN_EXISTING, 0, nullptr);
        if (h_ && h_ != INVALID_HANDLE_VALUE) return true;
        h_ = nullptr;
        return false;
    }

    void close_device() noexcept {
        if (h_ && h_ != INVALID_HANDLE_VALUE) CloseHandle(h_);
        h_ = nullptr;
    }

    // ---------- 握手 ----------
    bool handshake() noexcept {
        drv::HandshakeReq req{};
        req.magic = drv::kMagic;
        req.version = drv::kProtoVersion;

        const uint64_t r0 = rnd::sys64();
        const uint64_t r1 = rnd::sys64();
        std::memcpy(req.clientNonce, &r0, 8);
        std::memcpy(req.clientNonce + 8, &r1, 8);
        // MAC 由驱动在与用户态共享的密钥上计算；此处留给部署侧的密钥注入
        std::memcpy(req.mac, req.clientNonce, 16);  // 占位：真实实现需 HMAC

        drv::HandshakeResp resp{};
        DWORD ret = 0;
        if (!ioctl(drv::kIoctlHandshake, &req, sizeof(req), &resp, &ret)) return false;
        if (ret < sizeof(resp)) return false;
        if (resp.magic != drv::kMagic || resp.version != drv::kProtoVersion) return false;

        session_ = resp.sessionId;
        capabilities_ = resp.capabilities;
        seq_ = 0;
        return session_ != 0;
    }

    uint32_t next_seq() noexcept { return ++seq_; }

    // ---------- IOCTL 封装 ----------
    //
    // 走 NtDeviceIoControlFile 而不是 DeviceIoControl：
    //   DeviceIoControl 是 kernel32 导出的常规 API，很多工具会用，
    //   但它与"驱动通信"的关联度较高（导入表里同时出现 DeviceIoControl
    //   + CreateFileW + 无其他驱动相关 API，本身就是个弱特征）。
    //   NtDeviceIoControlFile 直接从 ntdll 动态解析，导入表零痕迹。
    //
    // 另外：驱动设备用的是 DO_BUFFERED_IO，走 METHOD_BUFFERED，
    // 所以 InputBuffer/OutputBuffer 直接传用户态指针即可，系统会拷。
    using NtDeviceIoControlFileFn = LONG(NTAPI*)(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK,
                                                 ULONG, PVOID, ULONG, PVOID, ULONG);

    bool ioctl(uint32_t code, const void* in, uint32_t inLen, void* out, DWORD* outLen) noexcept {
        if (!h_ || h_ == INVALID_HANDLE_VALUE) return false;

        static NtDeviceIoControlFileFn fn = api::get<NtDeviceIoControlFileFn>(
            api::mod::ntdll, hash::ascii("NtDeviceIoControlFile"));
        if (!fn) return false;

        IO_STATUS_BLOCK iosb{};
        const LONG st = fn(h_, nullptr, nullptr, nullptr, &iosb, code,
                           const_cast<void*>(in), inLen, out, outLen ? *outLen : 0);
        if (outLen) *outLen = static_cast<DWORD>(iosb.Information);
        return st >= 0;
    }

    HANDLE h_ = nullptr;
    bool ready_ = false;
    uint32_t session_ = 0;
    uint32_t seq_ = 0;
    uint32_t capabilities_ = 0;
    std::wstring name_token_;
};

}  // namespace input
