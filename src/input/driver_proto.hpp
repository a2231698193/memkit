// input/driver_proto.hpp —— 用户态 ↔ 驱动 的 IOCTL 协议
//
// 设计约束（决定了为什么长这样）：
//
//   1) 设备名随机化。固定 \Device\xxx 是最好抓的特征，所以设备名由用户态
//      生成后经配置传给驱动，驱动在 DriverEntry 时按参数注册。
//
//   2) 无 IRP_MJ_CREATE 白名单 = 任何进程都能打开。所以握手必须验签：
//      驱动只接受携带正确 HMAC 的请求，HMAC 密钥只存在于双方内存。
//
//   3) 不直接注入 SendInput。走 IOCTL 让驱动侧用
//      IoBuildDeviceIoControlRequest / 内部 HID 路径产生事件，
//      或由驱动回调到 kbdclass/mouclass 的 IRP，
//      消息链上不带 LLMHF_INJECTED。
//
//   4) 所有请求幂等 + 带序号，重放会被序号单调性挡掉。
#pragma once

#include <cstdint>

namespace drv {

// IOCTL 基址：选一个不常见的 function code，避免与其他驱动撞
// CTL_CODE(FILE_DEVICE_UNKNOWN=0x22, 0x800, METHOD_BUFFERED=0, FILE_ANY_ACCESS=0)
inline constexpr uint32_t kDeviceType = 0x22;
inline constexpr uint32_t kIoctlBase = 0x800;

constexpr uint32_t ctl_code(uint32_t fn) noexcept {
    // CTL_CODE 展开：(DeviceType<<16) | (Access<<14) | (Function<<2) | Method
    return (kDeviceType << 16) | (0u << 14) | ((kIoctlBase + fn) << 2) | 0u;
}

enum Fn : uint32_t {
    FnHandshake = 0,  // 交换 nonce，验证 HMAC，建立会话
    FnKeyEvent = 1,   // 键盘按下/抬起
    FnMouseMove = 2,  // 鼠标绝对移动
    FnMouseButton = 3,
    FnQueryState = 4, // 驱动自检：版本、会话数、拒绝计数
    FnClose = 5,      // 主动结束会话
};

inline constexpr uint32_t kIoctlHandshake = ctl_code(FnHandshake);
inline constexpr uint32_t kIoctlKeyEvent = ctl_code(FnKeyEvent);
inline constexpr uint32_t kIoctlMouseMove = ctl_code(FnMouseMove);
inline constexpr uint32_t kIoctlMouseButton = ctl_code(FnMouseButton);
inline constexpr uint32_t kIoctlQueryState = ctl_code(FnQueryState);
inline constexpr uint32_t kIoctlClose = ctl_code(FnClose);

inline constexpr uint32_t kProtoVersion = 1;
inline constexpr uint16_t kDeviceNameMaxChars = 120;

#pragma pack(push, 1)

// ---- 握手 ----
// 用户态 → 驱动：客户端 nonce + 协议版本
// 驱动 → 用户态：驱动 nonce + 能力位 + 会话 id
// 双向 HMAC-SHA256(nonce_client ‖ nonce_driver ‖ version)，前 16 字节
struct HandshakeReq {
    uint32_t magic;         // kMagic
    uint32_t version;
    uint8_t  clientNonce[16];
    uint8_t  mac[16];
};

struct HandshakeResp {
    uint32_t magic;
    uint32_t version;
    uint32_t capabilities;  // bit0 键盘, bit1 鼠标移动, bit2 鼠标按键
    uint32_t sessionId;
    uint8_t  driverNonce[16];
    uint8_t  mac[16];
};

// ---- 键盘事件 ----
// flags: bit0 = 抬起, bit1 = 扩展键(E0), bit2 = 使用扫描码而非 VK
struct KeyEvent {
    uint32_t sessionId;
    uint32_t seq;        // 单调递增，驱动侧拒绝回退
    uint16_t vk;
    uint16_t scan;       // 物理扫描码
    uint32_t flags;
    uint32_t holdUs;     // 期望保持时长（驱动侧尽力而为）
};

// ---- 鼠标移动 ----
// 绝对坐标，归一化到 [0, 65535]，与 MOUSEEVENTF_ABSOLUTE 语义一致
struct MouseMove {
    uint32_t sessionId;
    uint32_t seq;
    uint16_t nx;
    uint16_t ny;
    uint32_t flags;
};

// ---- 鼠标按键 ----
struct MouseButton {
    uint32_t sessionId;
    uint32_t seq;
    uint8_t  button;  // 0=左 1=右 2=中 3=侧键1 4=侧键2
    uint8_t  down;
    uint16_t pad;
    uint32_t flags;
};

// ---- 状态查询 ----
struct StateQuery {
    uint32_t sessionId;
    uint32_t seq;
};

struct StateResp {
    uint32_t version;
    uint32_t activeSessions;
    uint32_t rejectedRequests;  // 验签失败/序号异常计数，用于自检
    uint32_t uptimeMs;
    uint32_t capabilities;
};

#pragma pack(pop)

static_assert(sizeof(HandshakeReq) == 40, "HandshakeReq layout");
static_assert(sizeof(HandshakeResp) == 48, "HandshakeResp layout");
static_assert(sizeof(KeyEvent) == 20, "KeyEvent layout");
static_assert(sizeof(MouseMove) == 16, "MouseMove layout");
static_assert(sizeof(MouseButton) == 16, "MouseButton layout");

inline constexpr uint32_t kMagic = 0x53565244u;  // "DRVS"

}  // namespace drv
