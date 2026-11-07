/*++

Module Name:
    memkit_drv.c

Abstract:
    输入注入驱动。目标：产生"看起来来自真实硬件"的键盘/鼠标事件，
    使消息链上不出现 LLMHF_INJECTED 标记。

    架构决策（与用户态 driver_proto.hpp 严格对应）：

    1. 设备名随机化
       固定 \Device\xxx 是最容易抓的特征。设备名由用户态生成（随机 token），
       经加密配置传给安装脚本，脚本写到注册表 Parameters\DeviceName。
       DriverEntry 从注册表读，失败则用编译期默认（仅开发期）。

    2. 不做 IRP_MJ_CREATE 白名单
       做白名单反而引入"哪些进程能开"的固定逻辑。真正的门是 IOCTL 层：
       没密钥的进程能打开设备，但握手一定失败。

    3. 输入路径
       B. IOCTL_KEYBOARD_INSERT_DATA / IOCTL_MOUSE_INSERT_DATA 发给
          kbdclass / mouclass —— 官方接口，稳定。
       A. 直接调 KeyboardClassServiceCallback —— 产物与真实硬件中断完全一致，
          但依赖 kbdclass 内部实现，需版本适配。留编译期开关。

    4. 时序
       绝对不用固定间隔。holdUs 由用户态给区间，驱动侧在
       [holdUs*0.7, holdUs*1.3] 内随机；鼠标移动拆成多帧小幅累加。

    5. 不提供卸载例程
       防止被当作"可随时卸掉的可疑驱动"，也减少"频繁加载卸载"这一信号。

Environment:
    内核模式，x64。构建需要 WDK 10 + MSVC。

--*/

#include <ntifs.h>
#include <ntddk.h>
#include <ntddkbd.h>
#include <ntddmou.h>

/* -------------------------------------------------------------------------- */
/* 协议结构（与用户态 driver_proto.hpp 严格对应）                             */
/* -------------------------------------------------------------------------- */

#define MEMKIT_MAGIC         0x53565244u  /* "DRVS" */
#define MEMKIT_PROTO_VERSION 1u

#define MEMKIT_DEVICE_TYPE   0x22u
#define MEMKIT_IOCTL_BASE    0x800u

#define CTL_CODE_MEMKIT(fn) \
    ((MEMKIT_DEVICE_TYPE << 16) | ((MEMKIT_IOCTL_BASE + (fn)) << 2))

#define IOCTL_MEMKIT_HANDSHAKE   CTL_CODE_MEMKIT(0)
#define IOCTL_MEMKIT_KEYEVENT    CTL_CODE_MEMKIT(1)
#define IOCTL_MEMKIT_MOUSEMOVE   CTL_CODE_MEMKIT(2)
#define IOCTL_MEMKIT_MOUSEBUTTON CTL_CODE_MEMKIT(3)
#define IOCTL_MEMKIT_QUERYSTATE  CTL_CODE_MEMKIT(4)
#define IOCTL_MEMKIT_CLOSE       CTL_CODE_MEMKIT(5)

#define MEMKIT_TAG 'cvMW'   /* 'Wvmc' */

#define MEMKIT_CAP_KEYBOARD     0x00000001u
#define MEMKIT_CAP_MOUSE_MOVE   0x00000002u
#define MEMKIT_CAP_MOUSE_BUTTON 0x00000004u

#define MEMKIT_KEYUP            0x00000001u
#define MEMKIT_KEY_E0           0x00000002u
#define MEMKIT_KEY_SCANCODE     0x00000004u

#define MEMKIT_MAX_NAME         128
#define MEMKIT_MAX_SEQ_GAP      10000u

#pragma pack(push, 1)

typedef struct _MEMKIT_HANDSHAKE_REQ {
    ULONG  Magic;
    ULONG  Version;
    UCHAR  ClientNonce[16];
    UCHAR  Mac[16];
} MEMKIT_HANDSHAKE_REQ, *PMEMKIT_HANDSHAKE_REQ;

typedef struct _MEMKIT_HANDSHAKE_RESP {
    ULONG  Magic;
    ULONG  Version;
    ULONG  Capabilities;
    ULONG  SessionId;
    UCHAR  DriverNonce[16];
    UCHAR  Mac[16];
} MEMKIT_HANDSHAKE_RESP, *PMEMKIT_HANDSHAKE_RESP;

typedef struct _MEMKIT_KEY_EVENT {
    ULONG  SessionId;
    ULONG  Seq;
    USHORT Vk;
    USHORT Scan;
    ULONG  Flags;
    ULONG  HoldUs;
} MEMKIT_KEY_EVENT, *PMEMKIT_KEY_EVENT;

typedef struct _MEMKIT_MOUSE_MOVE {
    ULONG  SessionId;
    ULONG  Seq;
    USHORT Nx;
    USHORT Ny;
    ULONG  Flags;
} MEMKIT_MOUSE_MOVE, *PMEMKIT_MOUSE_MOVE;

typedef struct _MEMKIT_MOUSE_BUTTON {
    ULONG SessionId;
    ULONG Seq;
    UCHAR Button;
    UCHAR Down;
    USHORT Pad;
    ULONG Flags;
} MEMKIT_MOUSE_BUTTON, *PMEMKIT_MOUSE_BUTTON;

typedef struct _MEMKIT_STATE_QUERY {
    ULONG SessionId;
    ULONG Seq;
} MEMKIT_STATE_QUERY, *PMEMKIT_STATE_QUERY;

typedef struct _MEMKIT_STATE_RESP {
    ULONG Version;
    ULONG ActiveSessions;
    ULONG RejectedRequests;
    ULONG UptimeMs;
    ULONG Capabilities;
} MEMKIT_STATE_RESP, *PMEMKIT_STATE_RESP;

#pragma pack(pop)

/* 编译期校验：与用户态 static_assert 一一对应 */
C_ASSERT(sizeof(MEMKIT_HANDSHAKE_REQ) == 40);
C_ASSERT(sizeof(MEMKIT_HANDSHAKE_RESP) == 48);
C_ASSERT(sizeof(MEMKIT_KEY_EVENT) == 20);
C_ASSERT(sizeof(MEMKIT_MOUSE_MOVE) == 16);
C_ASSERT(sizeof(MEMKIT_MOUSE_BUTTON) == 16);

/* -------------------------------------------------------------------------- */
/* 设备扩展                                                                   */
/* -------------------------------------------------------------------------- */

typedef struct _MEMKIT_DEVICE_EXTENSION {
    FAST_MUTEX    Lock;
    ULONG         SessionId;          /* 0 = 未握手 */
    ULONG         LastSeq;            /* 单调序号，拒绝回退 */
    UCHAR         ClientNonce[16];
    UCHAR         DriverNonce[16];
    ULONG         RejectedRequests;
    LARGE_INTEGER StartTime;

    /* kbdclass / mouclass 的功能设备对象与文件对象（引用计数由我们持有） */
    PDEVICE_OBJECT KeyboardDevice;
    PFILE_OBJECT   KeyboardFile;
    PDEVICE_OBJECT MouseDevice;
    PFILE_OBJECT   MouseFile;
} MEMKIT_DEVICE_EXTENSION, *PMEMKIT_DEVICE_EXTENSION;

/*
 * 握手密钥。真实部署时由安装脚本写入注册表，DriverEntry 读出后
 * 与驱动内置盐混合。这里留占位。
 */
static UCHAR g_SharedKey[32] = { 0 };

/* -------------------------------------------------------------------------- */
/* 工具                                                                       */
/* -------------------------------------------------------------------------- */

/*
 * 轻量 PRNG。内核里不引入 CNG 的加密随机（开销大且拉进额外依赖）。
 * 目标只是"不可预测到无法用于统计还原"，不是密码学安全。
 */
static ULONG WvmRandom(PMEMKIT_DEVICE_EXTENSION Ext)
{
    LARGE_INTEGER t = KeQueryPerformanceCounter(NULL);
    ULONG x = t.LowPart ^ ((ULONG)t.HighPart << 13) ^ Ext->LastSeq;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return x;
}

/*
 * 人类化抖动：在 [us*7/10, us*13/10] 内均匀取值。
 * 真实键盘的按下-抬起间隔由人控制，驱动侧不该精确按时长抬起。
 */
static ULONG WvmJitterUs(PMEMKIT_DEVICE_EXTENSION Ext, ULONG Us)
{
    ULONG lo, span;
    if (Us == 0) {
        return 0;
    }
    lo = (Us * 7) / 10;
    span = (Us * 6) / 10 + 1;
    return lo + (WvmRandom(Ext) % span);
}

/*
 * MAC 占位实现。逐字节折叠 + 常数时间比较。
 *
 * 重要：这不是密码学安全的 MAC。上线前必须换成真 HMAC-SHA256
 * （内核里用 BCryptOpenAlgorithmProvider(BCRYPT_SHA256_ALGORITHM,
 *   BCRYPT_ALG_HANDLE_HMAC_FLAG)），否则任何人抓一次握手包就能伪造。
 */
static VOID WvmBuildMac(const UCHAR* Key, ULONG KeyLen,
                        const UCHAR* Data, ULONG DataLen,
                        UCHAR* Out)
{
    ULONG i;
    RtlZeroMemory(Out, 16);

    for (i = 0; i < KeyLen; i++) {
        Out[i & 0xF] ^= Key[i];
    }
    for (i = 0; i < DataLen; i++) {
        Out[i & 0xF] ^= Data[i];
        Out[(i * 7 + 3) & 0xF] = (UCHAR)(Out[(i * 7 + 3) & 0xF] + Data[i]);
    }
}

/* 常数时间比较：不用 memcmp，避免时序侧信道 */
static BOOLEAN WvmVerifyMac(const UCHAR* Key, ULONG KeyLen,
                            const UCHAR* Data, ULONG DataLen,
                            const UCHAR* Mac)
{
    UCHAR acc[16];
    UCHAR diff = 0;
    ULONG i;

    WvmBuildMac(Key, KeyLen, Data, DataLen, acc);
    for (i = 0; i < 16; i++) {
        diff = (UCHAR)(diff | (acc[i] ^ Mac[i]));
    }
    return (BOOLEAN)(diff == 0);
}

/* -------------------------------------------------------------------------- */
/* 连接 kbdclass / mouclass                                                   */
/* -------------------------------------------------------------------------- */

/*
 * 用公开 API IoGetDeviceObjectPointer 拿 kbdclass / mouclass 的 FDO。
 *
 * 为什么不用 ObReferenceObjectByName(\Driver\kbdclass)：
 *   ObReferenceObjectByName 与 IoDriverObjectType 都是未公开 API，
 *   WDK 头文件里没有声明。硬声明能编过，但那是"看起来能跑"的写法，
 *   换 WDK 版本或换 OS 版本就可能直接蓝屏。
 *
 * 设备命名（Windows 的固定约定，不是随机特征）：
 *   kbdclass  的 FDO: \Device\KeyboardClass0 / KeyboardClass1 / ...
 *   mouclass  的 FDO: \Device\PointerClass0  / PointerClass1  / ...
 *
 * IoGetDeviceObjectPointer 会返回一个 FILE_OBJECT（带引用）和一个
 * DEVICE_OBJECT（不带额外引用，随 FILE_OBJECT 一起失效）。
 * 所以我们持有 FILE_OBJECT，用它来发 IOCTL，而不是持有 DEVICE_OBJECT。
 */
static NTSTATUS WvmGetClassDevice(PCWSTR DevicePath,
                                  PDEVICE_OBJECT* OutDevice,
                                  PFILE_OBJECT* OutFile)
{
    NTSTATUS status;
    UNICODE_STRING path;
    PFILE_OBJECT fileObj = NULL;
    PDEVICE_OBJECT devObj = NULL;

    RtlInitUnicodeString(&path, DevicePath);

    status = IoGetDeviceObjectPointer(&path,
                                      FILE_READ_DATA | FILE_WRITE_DATA,
                                      &fileObj,
                                      &devObj);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    *OutDevice = devObj;
    *OutFile = fileObj;   /* 调用方负责 ObDereferenceObject */
    return STATUS_SUCCESS;
}

/* -------------------------------------------------------------------------- */
/* 输入注入：键盘                                                            */
/* -------------------------------------------------------------------------- */

/*
 * B 路径：向 kbdclass 设备发 IOCTL_KEYBOARD_INSERT_DATA。
 *
 * 注意两件事：
 *   1) IOCTL 名是 IOCTL_KEYBOARD_INSERT_DATA（不是 ..._INSERT_KEYBOARD_INPUT_DATA，
 *      后者是坊间误传，WDK 里没有）。
 *   2) 必须用 IoBuildDeviceIoControlRequest + IoCallDriver，不能传 FILE_OBJECT
 *      给 ZwDeviceIoControlFile（那需要 HANDLE）。
 *
 * 结构长度是关键：kbdclass 期望恰好 sizeof(KEYBOARD_INPUT_DATA) 的输入。
 */
static NTSTATUS WvmSendKeyEvent(PMEMKIT_DEVICE_EXTENSION Ext,
                                USHORT Vk, USHORT Scan, ULONG Flags)
{
    NTSTATUS status;
    KEYBOARD_INPUT_DATA input;
    PIRP irp;
    IO_STATUS_BLOCK iosb;
    KEVENT event;
    PDEVICE_OBJECT kbdDev;

    UNREFERENCED_PARAMETER(Vk);   /* 扫描码才是 kbdclass 关心的 */

    if (Ext->KeyboardDevice == NULL) {
        return STATUS_DEVICE_NOT_CONNECTED;
    }

    RtlZeroMemory(&input, sizeof(input));
    input.UnitId = 0;

    /*
     * E0 前缀处理：kbdclass 约定把 E0 折叠进 MakeCode 的高位。
     * 真实 101 键键盘的扩展键（方向键、右 Ctrl、Win 键）都带 E0。
     */
    if (Flags & MEMKIT_KEY_E0) {
        input.MakeCode = (USHORT)(0xE000 | (Scan & 0xFF));
    } else {
        input.MakeCode = (USHORT)(Scan & 0xFF);
    }

    input.Flags = (Flags & MEMKIT_KEYUP) ? KEY_BREAK : KEY_MAKE;
    input.Reserved = 0;
    input.ExtraInformation = 0;

    KeInitializeEvent(&event, NotificationEvent, FALSE);

    kbdDev = Ext->KeyboardDevice;

    /*
     * IoBuildDeviceIoControlRequest 的第二个参数是 DEVICE_OBJECT，
     * 但必须先通过 IoCallDriver 的栈位置设置 FILE_OBJECT ——
     * 对 kbdclass 来说，FileObject 必须非空，因为它的 dispatch 会读
     * stack->FileObject->FsContext（连接信息就存在那里）。
     */
    irp = IoBuildDeviceIoControlRequest(IOCTL_KEYBOARD_INSERT_DATA,
                                        kbdDev,
                                        &input, sizeof(input),
                                        NULL, 0,
                                        TRUE,
                                        &event, &iosb);
    if (irp != NULL && Ext->KeyboardFile != NULL) {
        PIO_STACK_LOCATION next = IoGetNextIrpStackLocation(irp);
        next->FileObject = Ext->KeyboardFile;
    }
    if (irp == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = IoCallDriver(kbdDev, irp);
    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = iosb.Status;
    }

    return status;
}

/* -------------------------------------------------------------------------- */
/* 输入注入：鼠标                                                            */
/* -------------------------------------------------------------------------- */

static NTSTATUS WvmSendMouseInput(PMEMKIT_DEVICE_EXTENSION Ext,
                                  USHORT Buttons, USHORT Nx, USHORT Ny, BOOLEAN Absolute)
{
    NTSTATUS status;
    MOUSE_INPUT_DATA input;
    PIRP irp;
    IO_STATUS_BLOCK iosb;
    KEVENT event;
    PDEVICE_OBJECT mouDev;

    if (Ext->MouseDevice == NULL) {
        return STATUS_DEVICE_NOT_CONNECTED;
    }

    RtlZeroMemory(&input, sizeof(input));
    input.UnitId = 0;
    input.ButtonFlags = Buttons;
    input.ButtonData = 0;
    input.LastX = (LONG)Nx;
    input.LastY = (LONG)Ny;
    input.ExtraInformation = 0;

    if (Absolute) {
        input.Flags = MOUSE_MOVE_ABSOLUTE | MOUSE_VIRTUAL_DESKTOP;
    }

    KeInitializeEvent(&event, NotificationEvent, FALSE);

    mouDev = Ext->MouseDevice;

    irp = IoBuildDeviceIoControlRequest(IOCTL_MOUSE_INSERT_DATA,
                                        mouDev,
                                        &input, sizeof(input),
                                        NULL, 0,
                                        TRUE,
                                        &event, &iosb);
    if (irp != NULL && Ext->MouseFile != NULL) {
        PIO_STACK_LOCATION next = IoGetNextIrpStackLocation(irp);
        next->FileObject = Ext->MouseFile;
    }
    if (irp == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = IoCallDriver(mouDev, irp);
    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = iosb.Status;
    }

    return status;
}

/* -------------------------------------------------------------------------- */
/* IOCTL 门禁                                                                 */
/* -------------------------------------------------------------------------- */

/*
 * 统一门禁，顺序不能变：
 *   1) 会话校验（握手前只放行 Handshake）
 *   2) 序号单调性 + 不能跳太远（防止重放已捕获的整段序列）
 *   3) 参数合法性（由各自 handler 追加）
 * 任何一步失败只累加计数，不返回差异化错误码 —— 不给分析者反馈。
 */
static BOOLEAN WvmGate(PMEMKIT_DEVICE_EXTENSION Ext, ULONG SessionId, ULONG Seq)
{
    if (SessionId == 0 || SessionId != Ext->SessionId) {
        Ext->RejectedRequests++;
        return FALSE;
    }
    if (Seq <= Ext->LastSeq || (Seq - Ext->LastSeq) > MEMKIT_MAX_SEQ_GAP) {
        Ext->RejectedRequests++;
        return FALSE;
    }
    Ext->LastSeq = Seq;
    return TRUE;
}

/* -------------------------------------------------------------------------- */
/* 各 IOCTL handler                                                           */
/* -------------------------------------------------------------------------- */

static NTSTATUS WvmHandleHandshake(PMEMKIT_DEVICE_EXTENSION Ext,
                                   PVOID InBuf, ULONG InLen,
                                   PVOID OutBuf, ULONG OutCap, PULONG OutLen)
{
    PMEMKIT_HANDSHAKE_REQ req;
    PMEMKIT_HANDSHAKE_RESP resp;
    UCHAR data[20];
    ULONG i;

    if (InLen < sizeof(MEMKIT_HANDSHAKE_REQ) || OutCap < sizeof(MEMKIT_HANDSHAKE_RESP)) {
        Ext->RejectedRequests++;
        return STATUS_BUFFER_TOO_SMALL;
    }

    req = (PMEMKIT_HANDSHAKE_REQ)InBuf;
    resp = (PMEMKIT_HANDSHAKE_RESP)OutBuf;

    if (req->Magic != MEMKIT_MAGIC || req->Version != MEMKIT_PROTO_VERSION) {
        Ext->RejectedRequests++;
        return STATUS_INVALID_PARAMETER;
    }

    /* 客户端 MAC = MAC(sharedKey, clientNonce ‖ version) */
    RtlCopyMemory(data, req->ClientNonce, 16);
    RtlCopyMemory(data + 16, &req->Version, 4);

    if (!WvmVerifyMac(g_SharedKey, sizeof(g_SharedKey), data, sizeof(data), req->Mac)) {
        Ext->RejectedRequests++;
        return STATUS_ACCESS_DENIED;
    }

    /* 生成驱动侧 nonce 与会话 id（随机，不递增，避免被猜） */
    for (i = 0; i < 16; i++) {
        Ext->DriverNonce[i] = (UCHAR)(WvmRandom(Ext) & 0xFF);
    }
    RtlCopyMemory(Ext->ClientNonce, req->ClientNonce, 16);
    Ext->SessionId = WvmRandom(Ext) | 1;   /* 保证非 0 */
    Ext->LastSeq = 0;

    resp->Magic = MEMKIT_MAGIC;
    resp->Version = MEMKIT_PROTO_VERSION;
    resp->Capabilities = MEMKIT_CAP_KEYBOARD | MEMKIT_CAP_MOUSE_MOVE | MEMKIT_CAP_MOUSE_BUTTON;
    resp->SessionId = Ext->SessionId;
    RtlCopyMemory(resp->DriverNonce, Ext->DriverNonce, 16);

    /* 服务端 MAC = MAC(sharedKey, driverNonce) */
    WvmBuildMac(g_SharedKey, sizeof(g_SharedKey), Ext->DriverNonce, 16, resp->Mac);

    *OutLen = sizeof(MEMKIT_HANDSHAKE_RESP);
    return STATUS_SUCCESS;
}

static NTSTATUS WvmHandleKeyEvent(PMEMKIT_DEVICE_EXTENSION Ext, PVOID InBuf, ULONG InLen)
{
    PMEMKIT_KEY_EVENT ev;

    if (InLen < sizeof(MEMKIT_KEY_EVENT)) {
        Ext->RejectedRequests++;
        return STATUS_BUFFER_TOO_SMALL;
    }

    ev = (PMEMKIT_KEY_EVENT)InBuf;
    if (!WvmGate(Ext, ev->SessionId, ev->Seq)) {
        return STATUS_ACCESS_DENIED;
    }

    /* 参数合法性：VK 与扫描码不能同时为 0 */
    if (ev->Vk == 0 && ev->Scan == 0) {
        Ext->RejectedRequests++;
        return STATUS_INVALID_PARAMETER;
    }

    /*
     * 时序抖动。B 路径下 kbdclass 会立即处理，我们没有
     * "按住 holdUs 再松开"的能力 —— 那需要起一个定时器线程，
     * 而新线程本身就是特征。改为：用户态负责发按下、等待、发抬起，
     * 等待时长由用户态 Humanizer 决定。这里只保留 jitter 调用，
     * 供 A 路径（直接调回调）使用。
     */
    (void)WvmJitterUs(Ext, ev->HoldUs);

    return WvmSendKeyEvent(Ext, ev->Vk, ev->Scan, ev->Flags);
}

static NTSTATUS WvmHandleMouseMove(PMEMKIT_DEVICE_EXTENSION Ext, PVOID InBuf, ULONG InLen)
{
    PMEMKIT_MOUSE_MOVE mv;

    if (InLen < sizeof(MEMKIT_MOUSE_MOVE)) {
        Ext->RejectedRequests++;
        return STATUS_BUFFER_TOO_SMALL;
    }

    mv = (PMEMKIT_MOUSE_MOVE)InBuf;
    if (!WvmGate(Ext, mv->SessionId, mv->Seq)) {
        return STATUS_ACCESS_DENIED;
    }

    return WvmSendMouseInput(Ext, 0, mv->Nx, mv->Ny, TRUE);
}

static NTSTATUS WvmHandleMouseButton(PMEMKIT_DEVICE_EXTENSION Ext, PVOID InBuf, ULONG InLen)
{
    PMEMKIT_MOUSE_BUTTON mb;
    USHORT flags;

    if (InLen < sizeof(MEMKIT_MOUSE_BUTTON)) {
        Ext->RejectedRequests++;
        return STATUS_BUFFER_TOO_SMALL;
    }

    mb = (PMEMKIT_MOUSE_BUTTON)InBuf;
    if (!WvmGate(Ext, mb->SessionId, mb->Seq)) {
        return STATUS_ACCESS_DENIED;
    }

    switch (mb->Button) {
        case 0: flags = mb->Down ? MOUSE_LEFT_BUTTON_DOWN : MOUSE_LEFT_BUTTON_UP; break;
        case 1: flags = mb->Down ? MOUSE_RIGHT_BUTTON_DOWN : MOUSE_RIGHT_BUTTON_UP; break;
        case 2: flags = mb->Down ? MOUSE_MIDDLE_BUTTON_DOWN : MOUSE_MIDDLE_BUTTON_UP; break;
        case 3: flags = mb->Down ? MOUSE_BUTTON_4_DOWN : MOUSE_BUTTON_4_UP; break;
        case 4: flags = mb->Down ? MOUSE_BUTTON_5_DOWN : MOUSE_BUTTON_5_UP; break;
        default:
            Ext->RejectedRequests++;
            return STATUS_INVALID_PARAMETER;
    }

    /* 按键事件相对坐标传 0，不移动光标 */
    return WvmSendMouseInput(Ext, flags, 0, 0, FALSE);
}

static NTSTATUS WvmHandleQueryState(PMEMKIT_DEVICE_EXTENSION Ext,
                                    PVOID InBuf, ULONG InLen,
                                    PVOID OutBuf, ULONG OutCap, PULONG OutLen)
{
    PMEMKIT_STATE_QUERY q;
    PMEMKIT_STATE_RESP resp;
    LARGE_INTEGER now;

    if (InLen < sizeof(MEMKIT_STATE_QUERY) || OutCap < sizeof(MEMKIT_STATE_RESP)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    q = (PMEMKIT_STATE_QUERY)InBuf;
    if (!WvmGate(Ext, q->SessionId, q->Seq)) {
        return STATUS_ACCESS_DENIED;
    }

    resp = (PMEMKIT_STATE_RESP)OutBuf;
    now = KeQueryPerformanceCounter(NULL);

    resp->Version = MEMKIT_PROTO_VERSION;
    resp->ActiveSessions = Ext->SessionId ? 1 : 0;
    resp->RejectedRequests = Ext->RejectedRequests;
    /* QPC 频率在 x64 上固定 10MHz，除以 10000 得毫秒 */
    resp->UptimeMs = (ULONG)((now.QuadPart - Ext->StartTime.QuadPart) / 10000);
    resp->Capabilities = MEMKIT_CAP_KEYBOARD | MEMKIT_CAP_MOUSE_MOVE | MEMKIT_CAP_MOUSE_BUTTON;

    *OutLen = sizeof(MEMKIT_STATE_RESP);
    return STATUS_SUCCESS;
}

/* -------------------------------------------------------------------------- */
/* IRP 分发                                                                   */
/* -------------------------------------------------------------------------- */

static NTSTATUS WvmDispatchCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS WvmDispatchClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS WvmDispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    PMEMKIT_DEVICE_EXTENSION ext = (PMEMKIT_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    PVOID systemBuf = Irp->AssociatedIrp.SystemBuffer;
    ULONG inLen = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outCap = stack->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;

    NTSTATUS status;
    ULONG outLen = 0;

    ExAcquireFastMutex(&ext->Lock);

    switch (code) {
        case IOCTL_MEMKIT_HANDSHAKE:
            status = WvmHandleHandshake(ext, systemBuf, inLen, systemBuf, outCap, &outLen);
            break;
        case IOCTL_MEMKIT_KEYEVENT:
            status = WvmHandleKeyEvent(ext, systemBuf, inLen);
            break;
        case IOCTL_MEMKIT_MOUSEMOVE:
            status = WvmHandleMouseMove(ext, systemBuf, inLen);
            break;
        case IOCTL_MEMKIT_MOUSEBUTTON:
            status = WvmHandleMouseButton(ext, systemBuf, inLen);
            break;
        case IOCTL_MEMKIT_QUERYSTATE:
            status = WvmHandleQueryState(ext, systemBuf, inLen, systemBuf, outCap, &outLen);
            break;
        case IOCTL_MEMKIT_CLOSE:
            ext->SessionId = 0;
            ext->LastSeq = 0;
            RtlZeroMemory(ext->ClientNonce, 16);
            RtlZeroMemory(ext->DriverNonce, 16);
            status = STATUS_SUCCESS;
            break;
        default:
            ext->RejectedRequests++;
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

    ExReleaseFastMutex(&ext->Lock);

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = outLen;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

/* -------------------------------------------------------------------------- */
/* 注册表读设备名                                                             */
/* -------------------------------------------------------------------------- */

static NTSTATUS WvmReadDeviceNameFromRegistry(PUNICODE_STRING Name)
{
    NTSTATUS status;
    HANDLE hKey = NULL;
    UNICODE_STRING keyPath;
    UNICODE_STRING valueName;
    OBJECT_ATTRIBUTES oa;
    UCHAR buffer[MEMKIT_MAX_NAME * sizeof(WCHAR) + 64];
    PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)buffer;
    ULONG retLen = 0;
    WCHAR fullName[MEMKIT_MAX_NAME];
    static const WCHAR prefix[] = L"\\Device\\";
    USHORT idx;

    RtlInitUnicodeString(&keyPath,
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\MemkitDrv\\Parameters");

    InitializeObjectAttributes(&oa, &keyPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                              NULL, NULL);

    status = ZwOpenKey(&hKey, KEY_READ, &oa);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlInitUnicodeString(&valueName, L"DeviceName");
    status = ZwQueryValueKey(hKey, &valueName, KeyValuePartialInformation,
                             info, sizeof(buffer), &retLen);

    if (NT_SUCCESS(status) && info->Type == REG_SZ && info->DataLength > 0 &&
        info->DataLength < (MEMKIT_MAX_NAME - 8) * sizeof(WCHAR)) {

        idx = (USHORT)((sizeof(prefix) - sizeof(WCHAR)) / sizeof(WCHAR));

        RtlCopyMemory(fullName, prefix, sizeof(prefix) - sizeof(WCHAR));
        RtlCopyMemory(&fullName[idx], info->Data, info->DataLength);
        idx = (USHORT)(idx + info->DataLength / sizeof(WCHAR));
        fullName[idx] = L'\0';

        RtlInitUnicodeString(Name, fullName);
    } else {
        status = STATUS_NOT_FOUND;
    }

    ZwClose(hKey);
    return status;
}

/* -------------------------------------------------------------------------- */
/* DriverEntry                                                                */
/* -------------------------------------------------------------------------- */

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    PDEVICE_OBJECT deviceObject = NULL;
    UNICODE_STRING deviceName;
    UNICODE_STRING symLinkName;
    WCHAR symLinkBuf[MEMKIT_MAX_NAME];
    PMEMKIT_DEVICE_EXTENSION ext;

    UNREFERENCED_PARAMETER(RegistryPath);

    /*
     * 设备名：优先注册表，失败则用编译期默认。
     * 实际部署时安装脚本会把随机 token 写进注册表。
     */
    RtlZeroMemory(&deviceName, sizeof(deviceName));
    status = WvmReadDeviceNameFromRegistry(&deviceName);
    if (!NT_SUCCESS(status)) {
        RtlInitUnicodeString(&deviceName, L"\\Device\\WvmcDev");
    }

    status = IoCreateDevice(DriverObject,
                            sizeof(MEMKIT_DEVICE_EXTENSION),
                            &deviceName,
                            FILE_DEVICE_UNKNOWN,
                            FILE_DEVICE_SECURE_OPEN,
                            FALSE,
                            &deviceObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    ext = (PMEMKIT_DEVICE_EXTENSION)deviceObject->DeviceExtension;
    RtlZeroMemory(ext, sizeof(*ext));
    ExInitializeFastMutex(&ext->Lock);
    ext->StartTime = KeQueryPerformanceCounter(NULL);

    /*
     * DO_BUFFERED_IO：由系统在 SystemBuffer 里拷入拷出。
     * 驱动侧不处理 MDL，减少 bug 面。
     */
    deviceObject->Flags |= DO_BUFFERED_IO;
    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    /*
     * 符号链接：用 \GLOBAL??\ 而不是 \DosDevices\。
     * 后者是每会话独立命名空间，服务上下文创建的链接在用户会话里未必可见。
     * 链接名从设备名派生（同样随机）。
     */
    {
        /*
         * 手工拼符号链接名，不用 RtlStringCchPrintfW。
         * 后者会拉进 __stdio_common_vswprintf（CRT 依赖），
         * 在 /NODEFAULTLIB 的内核链接里会失败。
         */
        static const WCHAR kGlobalPrefix[] = L"\\GLOBAL??\\";
        const USHORT prefixLen =
            (USHORT)((sizeof(kGlobalPrefix) - sizeof(WCHAR)) / sizeof(WCHAR));
        USHORT len = (USHORT)(deviceName.Length / sizeof(WCHAR));
        USHORT baseLen = (USHORT)(len > 7 ? 7 : len);
        const WCHAR* baseName = deviceName.Buffer + (len - baseLen);

        if (prefixLen + baseLen + 1 > MEMKIT_MAX_NAME) {
            IoDeleteDevice(deviceObject);
            return STATUS_INVALID_PARAMETER;
        }
        RtlCopyMemory(symLinkBuf, kGlobalPrefix, sizeof(kGlobalPrefix) - sizeof(WCHAR));
        RtlCopyMemory(&symLinkBuf[prefixLen], baseName, baseLen * sizeof(WCHAR));
        symLinkBuf[prefixLen + baseLen] = L'\0';

        RtlInitUnicodeString(&symLinkName, symLinkBuf);

        status = IoCreateSymbolicLink(&symLinkName, &deviceName);
        if (!NT_SUCCESS(status)) {
            IoDeleteDevice(deviceObject);
            return status;
        }
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = WvmDispatchCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = WvmDispatchClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = WvmDispatchDeviceControl;

    /*
     * 不设 DriverUnload。
     * 理由：防止被当作"可随时卸掉的可疑驱动"，也减少"频繁加载卸载"这一信号。
     * 换版本需要重启 —— 有意为之。
     */

    /* 连接 kbdclass / mouclass（失败不阻断加载，用户态会看到能力位为空） */
    if (!NT_SUCCESS(WvmGetClassDevice(L"\\Device\\KeyboardClass0",
                                      &ext->KeyboardDevice, &ext->KeyboardFile))) {
        ext->KeyboardDevice = NULL;
        ext->KeyboardFile = NULL;
    }
    if (!NT_SUCCESS(WvmGetClassDevice(L"\\Device\\PointerClass0",
                                      &ext->MouseDevice, &ext->MouseFile))) {
        ext->MouseDevice = NULL;
        ext->MouseFile = NULL;
    }

    return STATUS_SUCCESS;
}
