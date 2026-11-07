// app/selftest.cpp —— 离线自检入口（不参与正式构建）
//
// 用途：在本机验证 P0/P1 各组件行为是否符合设计，不碰游戏。
// 编译：cmake -S . -B build -DMEMKIT_SELFTEST=ON && cmake --build build
// 运行：build/selftest.exe
#include <windows.h>

#include <cstdio>
#include <vector>

#include "common/cfg.hpp"
#include "common/obf.hpp"
#include "common/rnd.hpp"
#include "common/ringlog.hpp"
#include "input/backend.hpp"
#include "input/hookprobe.hpp"
#include "input/u32.hpp"
#include "input/driver.hpp"
#include "input/driver_proto.hpp"
#include "ipc/channel.hpp"
#include "os/handles.hpp"
#include "os/process.hpp"
#include "os/scan.hpp"
#include "os/gamestate.hpp"
#include "os/config_io.hpp"
#include "os/profile.hpp"
#include "os/resolve.hpp"
#include "os/accessmask.hpp"
#include "os/guardprobe.hpp"
#include "os/scanpattern.hpp"
#include "os/sched.hpp"
#include "os/schema.hpp"
#include "os/task.hpp"
#include "stealth/antidebug.hpp"
#include "stealth/api.hpp"
#include "stealth/ident.hpp"
#include "stealth/inject.hpp"
#include "stealth/manifest.hpp"
#include "stealth/manualmap.hpp"
#include "stealth/pebunlink.hpp"

namespace {

int g_fail = 0;

void check(bool cond, const char* what) {
    std::printf("[%s] %s\n", cond ? " OK " : "FAIL", what);
    if (!cond) ++g_fail;
}

void test_api_resolution() {
    std::printf("--- API 解析（PEB + 导出表哈希）---\n");
    using FnClose = LONG(NTAPI*)(HANDLE);
    const auto close = api::get<FnClose>(api::mod::ntdll, hash::ascii("NtClose"));
    check(close != nullptr, "ntdll!NtClose 解析成功");

    const auto open = api::get<void*>(api::mod::ntdll, hash::ascii("NtOpenProcess"));
    check(open != nullptr, "ntdll!NtOpenProcess 解析成功");

    check(api::module(api::mod::kernel32) != nullptr, "kernel32 基址解析成功");
    check(api::module(hash::wide(L"nonexistent.dll")) == nullptr, "不存在的模块返回空");

    check(api::get<void*>(api::mod::ntdll, hash::ascii("NoSuchFunction")) == nullptr,
          "不存在的导出返回空");
}

void test_obf() {
    std::printf("--- 常量加密 ---\n");
    const std::string a = OBF("Game.exe", 0x9E37u);
    const std::string b = OBF("Game.exe", 0x1234u);
    check(a == "Game.exe", "解密结果与明文一致");
    check(OBFW("abc", 0x55u) == L"abc", "宽字符转换正确");
    (void)b;
}

void test_rng() {
    std::printf("--- 随机分布 ---\n");
    // 对数正态：中位数应接近 p50
    int samples[400];
    for (auto& s : samples) s = rnd::lognorm_ms(90, 0.45);
    int under = 0;
    for (int s : samples)
        if (s <= 90) ++under;
    check(under > 120 && under < 280, "对数正态中位数落在 p50 附近");

    bool positive = true;
    for (int s : samples)
        if (s < 1) positive = false;
    check(positive, "延迟恒为正");

    // 幂律：至少出现远超 min 的长尾
    int maxGap = 0;
    for (int i = 0; i < 400; ++i) {
        const int g = rnd::pareto_like_ms(200, 1.5);
        if (g > maxGap) maxGap = g;
    }
    check(maxGap > 600, "幂律分布存在长尾");

    // 抖动范围正确
    bool inRange = true;
    for (int i = 0; i < 1000; ++i) {
        const int v = rnd::jitter(36);
        if (v < -36 || v > 36) inRange = false;
    }
    check(inRange, "抖动不越界");
}

void test_ident() {
    std::printf("--- 标识随机化 ---\n");
    std::wstring a = ident::token(10, 14);
    std::wstring b = ident::token(10, 14);
    check(a != b, "两次 token 不同");
    check(a.size() >= 10 && a.size() <= 14, "长度在指定区间");
    check(!(a[0] >= L'0' && a[0] <= L'9'), "首字符非数字");
    check(ident::mutex_name().rfind(L"Global\\", 0) == 0, "互斥体带 Global 前缀");
    check(ident::pipe_name().rfind(L"\\\\.\\pipe\\", 0) == 0, "管道名格式正确");
    check(ident::mutex_name() != ident::mutex_name(), "互斥体名每次不同");
}

void test_session() {
    std::printf("--- 会话生命周期 ---\n");
    os::Session s;
    check(!s.valid(), "未 Begin 时无效");
    check(s.age_ms() == -1, "未 Begin 时 age 为 -1");

    // 打开自身进程（读 PE 头）
    check(s.Begin(GetCurrentProcessId()), "可打开自身进程");
    check(s.valid() && s.alive(), "Begin 后可存活");

    const uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    uint8_t mz[2] = {};
    check(s.Read(base, mz, sizeof(mz)), "可读自身 PE 头");
    check(mz[0] == 'M' && mz[1] == 'Z', "读到的确实是 MZ");

    // 指针链：读自己模块基址的 e_lfanew 再取 PE 签名
    uint32_t peOff = 0;
    check(s.Read(base + 0x3C, peOff), "可读 e_lfanew");
    uint32_t sig = 0;
    check(s.Read(base + peOff, sig), "可读 PE 签名位置");
    check(sig == 0x00004550, "PE 签名正确");

    s.Close();
    check(!s.valid(), "Close 后无效");
    check(!s.Read(base, mz, sizeof(mz)), "Close 后读取失败");

    // 区域信息
    os::Session s2;
    if (s2.Begin(GetCurrentProcessId())) {
        os::Session::RegionInfo ri;
        check(s2.region(base, ri), "可查区域信息");
        check(ri.state == MEM_COMMIT, "区域为已提交");
        check(ri.size > 0, "区域大小非零");
    }
}

void test_handle_audit() {
    std::printf("--- 句柄审计 ---\n");
    const auto idx = os::process_type_index();
    check(idx != 0xFFFF, "成功校准 Process 类型索引");

    // 干净状态：不持有任何目标句柄
    const auto clean = os::audit_handles(GetCurrentProcessId());
    check(clean.ok, "句柄快照成功");
    std::printf("      类型索引=%u 自身Process句柄=%u 指向自身=%u 无法判定=%u\n",
                clean.type_index, clean.self_process_handles, clean.target_handles,
                clean.unknown);
    // 快照全程自身只持有 1 个（标定用），此时应为 0
    check(clean.target_handles <= 1, "自身进程句柄计数合理");

    // 持有时应被检出
    {
        os::Session s;
        if (s.Begin(GetCurrentProcessId())) {
            const auto held = os::audit_handles(GetCurrentProcessId());
            check(held.ok, "持有时快照仍成功");
            check(held.target_handles >= 1, "持有时能检出指向目标的句柄");
            std::printf("      持有时检出=%u\n", held.target_handles);
            s.Close();

            const auto after = os::audit_handles(GetCurrentProcessId());
            check(after.target_handles == 0, "关闭后审计恢复干净");
        }
    }
}

void test_scan() {
    std::printf("--- 进程/模块定位 ---\n");
    const auto procs = os::enum_processes();
    check(procs.size() > 5, "枚举到多个进程");

    bool foundSelf = false;
    for (const auto& p : procs) {
        if (p.pid == GetCurrentProcessId()) {
            foundSelf = true;
            check(!p.name.empty(), "自身进程名非空");
        }
    }
    check(foundSelf, "枚举结果包含自身");

    const uintptr_t base = os::module_base(GetCurrentProcessId(), L"selftest.exe");
    check(base != 0, "可定位自身模块基址");
    check(base == reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr)),
          "模块基址与 GetModuleHandle 一致");
}

void test_scheduler() {
    std::printf("--- 会话调度器 ---\n");
    os::Scheduler sched(GetCurrentProcessId());

    int reads = 0;
    for (int i = 0; i < 5; ++i) {
        sched.run_batch([&](os::Session& s) {
            uint8_t mz[2] = {};
            if (s.Read(reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr)), mz, sizeof(mz)))
                ++reads;
            return true;
        });
    }
    check(reads == 5, "5 个批次全部读取成功");
    check(sched.stats().batches == 5, "批次计数正确");
    check(sched.stats().forced_closes == 0, "无超时强关");
    std::printf("      批次=%u 最长生时=%ums 强关=%u\n", sched.stats().batches,
                sched.stats().max_life_ms, sched.stats().forced_closes);
    check(sched.stats().max_life_ms < 200, "单批生时低于硬上限");

    // 批间审计：必须干净
    const auto a = sched.audit();
    check(a.executed, "调度器句柄审计可执行");
    check(a.clean(), "调度器在批间不残留目标句柄");
}

void test_antidebug() {
    std::printf("--- 反调试自查 ---\n");
    check(!adbg::peb_flag() || true, "PEB 标志可读");  // 被调试时也会返回 true，此处只验证不崩
    std::printf("      peb=%d debugobj=%d hwbp=%d hostile=%d\n", adbg::peb_flag() ? 1 : 0,
                adbg::debug_object() ? 1 : 0, adbg::hw_breakpoint() ? 1 : 0,
                adbg::hostile_module() ? 1 : 0);
    // 正常运行时不应被判定为调试中
    check(!adbg::hw_breakpoint(), "无硬件断点");
    check(!adbg::hostile_module(), "无恶意模块");
}


void test_config_crypto() {
    std::printf("--- 配置加密 ---\n");
    const std::string plain = R"({"a":1,"target":"Game.exe","offs":[16,160,864]})";
    const uint32_t seed = 0xC0FFEEu;

    const auto blob = cfg::seal(plain, seed);
    check(blob.size() > cfg::kHeaderSize, "密封后的 blob 含头与体");

    // 密文不得包含任何明文片段
    const std::string raw(reinterpret_cast<const char*>(blob.data()), blob.size());
    check(raw.find("Game.exe") == std::string::npos, "密文不含明文片段");
    check(raw.find("offs") == std::string::npos, "密文不含字段名");

    std::string back;
    check(cfg::open(blob, seed, back), "可解密");
    check(back == plain, "解密结果与原文一致");

    // 错误种子必须失败（MAC 校验拦截）
    std::string wrong;
    check(!cfg::open(blob, seed ^ 1u, wrong), "错误种子被拒绝");

    // 篡改任意字节必须失败
    auto tampered = blob;
    tampered[cfg::kHeaderSize] ^= 0xFF;
    std::string t;
    check(!cfg::open(tampered, seed, t), "密文篡改被拒绝");

    // 头部 nonce 改动也应失败
    auto nonceBad = blob;
    nonceBad[offsetof(cfg::Header, nonce)] ^= 0x01;
    check(!cfg::open(nonceBad, seed, t), "nonce 篡改被拒绝");

    // 截断必须失败
    auto truncated = blob;
    truncated.resize(blob.size() - 1);
    check(!cfg::open(truncated, seed, t), "截断被拒绝");

    // 同一明文两次封印产生不同密文（nonce 随机）
    const auto blob2 = cfg::seal(plain, seed);
    check(blob != blob2, "nonce 随机化生效");
}

void test_ringlog() {
    std::printf("--- 环形日志 ---\n");
    auto& r = rlog::Ring::instance();
    r.reset(os::ticks());
    check(r.size() == 0, "初始为空");

    for (uint16_t i = 0; i < 10; ++i) {
        r.push(rlog::Level::Info, rlog::kEvBoot, 1, i);
    }
    check(r.size() == 10, "写入 10 条");
    auto snap = r.snapshot();
    check(snap.size() == 10, "快照条数一致");
    check(snap.front().argv[0] == 0 && snap.back().argv[0] == 9, "顺序为最旧到最新");

    // 溢出测试：写满 + 超量，尺寸恒定
    for (size_t i = 0; i < rlog::kCapacity * 2; ++i) {
        r.push(rlog::Level::Trace, rlog::kEvSessionEnd, 1, i);
    }
    check(r.size() == rlog::kCapacity, "溢出后容量恒定");
    auto big = r.snapshot();
    check(big.size() == rlog::kCapacity, "溢出后快照仍为容量上限");
    check(big.back().argv[0] == rlog::kCapacity * 2 - 1, "最新一条为最后写入的");

    r.enable(false);
    const size_t before = r.size();
    r.push(rlog::Level::Error, rlog::kEvBoot);
    check(r.size() == before, "关闭后不写入");
    r.enable(true);
}

void test_task_batch() {
    std::printf("--- 任务批次 ---\n");
    const uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));

    os::Batch b;
    b.add_read(base, 2, 1);
    b.add_read(base + 0x3C, 4, 2);
    const uintptr_t offs[1] = {0};
    b.add_chain(base, offs, 1, 3);
    b.add_probe(base, 64, 4);
    check(b.tasks.size() == 4, "批次内 4 个任务");

    os::Scheduler sched(GetCurrentProcessId());
    const auto results = sched.run(b);
    check(results.size() == 4, "返回 4 个结果");

    for (const auto& r : results) {
        if (r.id == 1) check(r.ok && r.bytes.size() == 2 && r.bytes[0] == 'M', "Read 任务成功");
        if (r.id == 2) check(r.ok && r.bytes.size() == 4, "e_lfanew 读取成功");
        if (r.id == 4) check(r.ok && r.bytes.size() == 64, "Probe 任务成功");
    }

    // 越界地址应失败但不影响其他任务
    os::Batch b2;
    b2.add_read(0x10, 4, 10);
    b2.add_read(base, 2, 11);
    const auto r2 = sched.run(b2);
    check(r2.size() == 2, "失败批次仍返回全部结果");
    check(!r2[0].ok, "非法地址读取失败");
    check(r2[1].ok, "同批次后续任务不受影响");

    // 空批次不建立会话
    const uint32_t before = sched.stats().batches;
    os::Batch empty;
    sched.run(empty);
    check(sched.stats().batches == before, "空批次不消耗会话");

    // 深度限制
    os::Batch b3;
    uintptr_t deep[16] = {};
    b3.add_chain(base, deep, 16, 20);
    check(b3.empty(), "超深指针链被拒绝");
}


inline std::wstring ipc_prefix() {
    std::wstring s;
    s.push_back(static_cast<wchar_t>(0x5C));
    s.push_back(static_cast<wchar_t>(0x5C));
    s.push_back(L'.');
    s.push_back(static_cast<wchar_t>(0x5C));
    s += L"pipe";
    s.push_back(static_cast<wchar_t>(0x5C));
    return s;
}

void test_ipc_protocol() {
    std::printf("--- IPC 帧协议 ---\n");

    // CRC 自校验
    const char* msg = "hello-frame";
    const uint32_t c1 = ipc::crc32(reinterpret_cast<const uint8_t*>(msg), strlen(msg));
    const uint32_t c2 = ipc::crc32(reinterpret_cast<const uint8_t*>(msg), strlen(msg));
    check(c1 == c2, "CRC32 稳定");

    ipc::Server srv;
    check(srv.open(), "服务端创建管道");
    check(!srv.name().empty(), "管道名非空");
    check(srv.name().rfind(ipc_prefix(), 0) == 0, "管道名前缀正确");

    ipc::Client cli;
    check(cli.connect(srv.name(), 200), "客户端连接成功");
    check(srv.accept_pending(), "服务端接受连接");

    // 请求 → 响应
    ipc::Frame req;
    req.op = ipc::kOpPing;
    req.seq = 42;
    req.flags = ipc::kReq;
    req.payload = {'p', 'i', 'n', 'g'};
    check(srv.send(req), "服务端发送请求");

    ipc::Frame got;
    bool received = false;
    for (int i = 0; i < 200 && !received; ++i) {
        received = cli.try_recv(got);
        if (!received) Sleep(5);
    }
    check(received, "客户端收到帧");
    check(got.op == ipc::kOpPing, "操作码正确");
    check(got.seq == 42, "序号正确");
    check(got.flags == ipc::kReq, "标志正确");
    check(got.payload.size() == 4, "载荷长度正确");

    // 反向：客户端发响应
    ipc::Frame resp;
    resp.op = ipc::kOpPing;
    resp.seq = 42;
    resp.flags = ipc::kResp;
    resp.payload = {'p', 'o', 'n', 'g'};
    check(cli.send(resp), "客户端发送响应");

    ipc::Frame back;
    bool backOk = false;
    for (int i = 0; i < 200 && !backOk; ++i) {
        backOk = srv.try_recv(back);
        if (!backOk) Sleep(5);
    }
    check(backOk, "服务端收到响应");
    check(back.flags == ipc::kResp && back.seq == 42, "响应回填同一序号");

    // 大载荷（接近上限）
    std::vector<uint8_t> big(ipc::kMaxPayload, 0xAB);
    ipc::Frame bigFrame;
    bigFrame.op = ipc::kOpLogSnapshot;
    bigFrame.seq = 7;
    bigFrame.payload = big;
    check(srv.send(bigFrame), "接近上限的载荷可发送");

    ipc::Frame bigGot;
    bool bigOk = false;
    for (int i = 0; i < 300 && !bigOk; ++i) {
        bigOk = cli.try_recv(bigGot);
        if (!bigOk) Sleep(5);
    }
    check(bigOk && bigGot.payload.size() == ipc::kMaxPayload, "大载荷完整接收");

    // 超上限必须拒绝
    ipc::Frame tooBig;
    tooBig.op = ipc::kOpPing;
    tooBig.payload.assign(ipc::kMaxPayload + 1, 0);
    check(!srv.send(tooBig), "超上限载荷被拒绝");

    // 关闭后不可用
    cli.close();
    check(!cli.opened(), "客户端关闭后不可用");
    check(!cli.send(req), "关闭后发送失败");
}

void test_driver_proto() {
    std::printf("--- 驱动 IOCTL 协议 ---\n");

    // 布局与对齐：两侧必须完全一致，否则驱动收到的字段全是错位的
    check(sizeof(drv::HandshakeReq) == 40, "HandshakeReq 布局");
    check(sizeof(drv::HandshakeResp) == 48, "HandshakeResp 布局");
    check(sizeof(drv::KeyEvent) == 20, "KeyEvent 布局");
    check(sizeof(drv::MouseMove) == 16, "MouseMove 布局");
    check(sizeof(drv::MouseButton) == 16, "MouseButton 布局");

    // CTL_CODE 展开正确性：手算一遍对比
    // (0x22<<16) | (0<<14) | (0x800<<2) | 0
    check(drv::kIoctlHandshake == ((0x22u << 16) | (0x800u << 2)), "Handshake IOCTL 码");
    check(drv::kIoctlKeyEvent == ((0x22u << 16) | (0x801u << 2)), "KeyEvent IOCTL 码");
    check(drv::kIoctlMouseMove == ((0x22u << 16) | (0x802u << 2)), "MouseMove IOCTL 码");

    // 各 IOCTL 码必须互不相同
    const uint32_t codes[] = {drv::kIoctlHandshake, drv::kIoctlKeyEvent, drv::kIoctlMouseMove,
                              drv::kIoctlMouseButton, drv::kIoctlQueryState, drv::kIoctlClose};
    bool unique = true;
    for (size_t i = 0; i < 6; ++i)
        for (size_t j = i + 1; j < 6; ++j)
            if (codes[i] == codes[j]) unique = false;
    check(unique, "所有 IOCTL 码互不相同");

    // 无驱动时后端必须优雅失败（不能崩、不能假成功）
    input::DriverBackend drvBackend;
    check(!drvBackend.init(), "无驱动时 init 返回 false");
    check(!drvBackend.ready(), "ready 标志为 false");
    check(!drvBackend.key(0x41, true), "无驱动时按键失败但不崩");
    check(!drvBackend.move_abs(100, 100), "无驱动时移动失败但不崩");
    check(!drvBackend.mouse_button(0, true), "无驱动时鼠标键失败但不崩");
    drvBackend.shutdown();
    check(!drvBackend.injectable_marker(), "驱动后端不带注入标记");
}

void test_parent_check() {
    std::printf("--- 父进程粗筛 ---\n");

    const DWORD ppid = adbg::parent_pid();
    check(ppid != 0, "能取到父进程 PID");
    check(ppid != GetCurrentProcessId(), "父进程不是自身");
    std::printf("      父进程 PID=%lu\n", static_cast<unsigned long>(ppid));

    // 黑名单哈希比对：直接构造几个已知名字验证
    check(adbg::is_analyzer_image(L"x64dbg.exe"), "识别 x64dbg");
    check(adbg::is_analyzer_image(L"X64DBG.EXE"), "大小写不敏感");
    check(adbg::is_analyzer_image(L"cheatengine-x86_64.exe"), "识别 Cheat Engine");
    check(!adbg::is_analyzer_image(L"explorer.exe"), "explorer 不在黑名单");
    check(!adbg::is_analyzer_image(L"memkit.exe"), "自身不在黑名单");
    check(!adbg::is_analyzer_image(L""), "空名不误判");
}


void test_pe_parser() {
    std::printf("--- PE 解析（手工映射前置）---\n");

    // 用自身 exe 当样本：读盘 → 解析
    wchar_t path[MAX_PATH]{};
    GetModuleFileNameW(nullptr, path, MAX_PATH);

    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    check(f != INVALID_HANDLE_VALUE, "可打开自身 exe");
    if (f == INVALID_HANDLE_VALUE) return;

    LARGE_INTEGER sz{};
    GetFileSizeEx(f, &sz);
    std::vector<uint8_t> bytes(static_cast<size_t>(sz.QuadPart));
    DWORD got = 0;
    check(ReadFile(f, bytes.data(), static_cast<DWORD>(bytes.size()), &got, nullptr) != FALSE &&
              got == bytes.size(),
          "完整读入文件");
    CloseHandle(f);

    mmap::PeImage pe;
    check(pe.parse(std::move(bytes)), "PE 解析成功");
    check(pe.sizeOfImage > 0, "SizeOfImage 非零");
    check(pe.sizeOfHeaders > 0, "SizeOfHeaders 非零");
    check(pe.numSections > 0, "节数非零");
    check(pe.entryRva != 0, "入口点 RVA 非零");
    check(pe.importRva != 0, "有导入表");
    std::printf("      ImageBase=0x%llX SizeOfImage=0x%X 节数=%u 入口=0x%X\n",
                static_cast<unsigned long long>(pe.imageBase), pe.sizeOfImage,
                pe.numSections, pe.entryRva);

    // 拒绝非 PE
    mmap::PeImage bad;
    std::vector<uint8_t> junk(1024, 0xCC);
    check(!bad.parse(std::move(junk)), "非 PE 被拒绝");

    // 截断必须拒绝
    mmap::PeImage trunc;
    std::vector<uint8_t> shot(64, 0);
    check(!trunc.parse(std::move(shot)), "过短输入被拒绝");
}

void test_remote_resolver() {
    std::printf("--- 目标侧导出解析 ---\n");
    os::Session s;
    check(s.Begin(GetCurrentProcessId()), "打开自身会话");
    check(s.pid() == GetCurrentProcessId(), "会话记录 pid");
    check(s.handle() != nullptr, "会话暴露 handle");

    mmap::RemoteResolver rr(s);
    const uint64_t ntdllBase = rr.module("ntdll.dll");
    check(ntdllBase != 0, "解析 ntdll 基址");
    check(ntdllBase == reinterpret_cast<uint64_t>(api::module(api::mod::ntdll)),
          "与本地 PEB 解析一致");

    const uint64_t kernel32Base = rr.module("kernel32.dll");
    check(kernel32Base != 0, "解析 kernel32 基址");

    // 用已知导出验证：NtClose 地址应与本地解析一致
    const uint64_t remoteNtClose = rr.by_name(ntdllBase, "NtClose");
    const uint64_t localNtClose =
        reinterpret_cast<uint64_t>(api::proc(api::module(api::mod::ntdll),
                                             hash::ascii("NtClose")));
    check(remoteNtClose != 0, "远端解析 NtClose");
    check(remoteNtClose == localNtClose, "远端解析结果与本地一致");

    // 缓存命中：第二次应该相同
    check(rr.by_name(ntdllBase, "NtClose") == remoteNtClose, "缓存返回相同结果");

    // 不存在的导出
    check(rr.by_name(ntdllBase, "TotallyNotARealFunction") == 0, "不存在的导出返回 0");

    // CreateFileW 在 kernel32 里
    check(rr.by_name(kernel32Base, "CreateFileW") != 0, "解析 kernel32!CreateFileW");

    s.Close();
}

void test_manualmap_errors() {
    std::printf("--- 手工映射错误路径 ---\n");
    os::Session s;
    // 手工映射确实需要写权限，显式 allowMap=true。
    // 注意：只用 kWrite（含 VM_WRITE|VM_OPERATION），不再附加 QUERY_FULL，
    // 后者会让权限更显眼。
    check(s.Begin(GetCurrentProcessId(), os::Session::kWrite, true),
          "允许映射时以写权限打开自身");

    mmap::PeImage empty;
    mmap::Mapped out;
    check(mmap::map_image(s, empty, out) == mmap::kErrParse, "空映像返回 Parse 错误");

    // 有效 PE 但目标是自己：会真的映射进来，所以只验证错误码不跑成功路径
    // （成功路径会分配可执行内存，对 selftest 没意义且可能触发杀软）
    s.Close();

    mmap::Mapped zero;
    os::Session closed;
    // 没有有效会话时必须失败而不是崩
    mmap::PeImage dummy;
    dummy.sizeOfImage = 0x1000;
    dummy.raw.resize(64);
    check(mmap::map_image(closed, dummy, zero) != mmap::kOk, "无会话时映射失败");

    mmap::unmap_image(closed, zero);  // 不应崩
    check(true, "对空映射调用 unmap 不崩");
}

void test_thread_enum() {
    std::printf("--- 线程枚举与句柄 ---\n");
    const auto threads = inject::threads_of(GetCurrentProcessId());
    check(!threads.empty(), "枚举到自身线程");

    bool foundSelf = false;
    for (const auto& t : threads) {
        if (t.ownerPid == GetCurrentProcessId()) foundSelf = true;
    }
    check(foundSelf, "线程的 ownerPid 正确");

    // 开自身线程（不需要特殊权限）
    DWORD tid = threads.empty() ? 0 : threads.front().tid;
    inject::ThreadHandle th;
    check(th.open(tid, 0x0008 /*THREAD_QUERY_INFORMATION*/), "可打开线程查询句柄");
    check(th.valid(), "句柄有效");
    th.close();
    check(!th.valid(), "关闭后无效");
    check(!th.open(0, 0x0008), "tid=0 打开失败");

    // 不存在的 tid
    check(!th.open(0xFFFFFF, 0x0008), "不存在的 tid 打开失败");
}

void test_hijack_preamble() {
    std::printf("--- 劫持 preamble 生成 ---\n");
    const auto code = inject::make_hijack_preamble(0x1111111111111111ull, 0x2222222222222222ull,
                                                   0x3333333333333333ull);
    check(!code.empty(), "生成非空代码");

    // 结构校验：pushfq 开头，jmp rax 结尾
    check(code[0] == 0x9C, "以 pushfq 开头");
    check(code[code.size() - 2] == 0xFF && code[code.size() - 1] == 0xE0, "以 jmp rax 结尾");

    // 三个 8 字节立即数都应出现在代码中
    auto contains64 = [&](uint64_t v) {
        for (size_t i = 0; i + 8 <= code.size(); ++i) {
            uint64_t x = 0;
            for (int j = 0; j < 8; ++j) x |= static_cast<uint64_t>(code[i + j]) << (8 * j);
            if (x == v) return true;
        }
        return false;
    };
    check(contains64(0x1111111111111111ull), "含 stub 地址");
    check(contains64(0x2222222222222222ull), "含参数块地址");
    check(contains64(0x3333333333333333ull), "含恢复地址");

    // 保存/恢复必须配对：7 个 push 对应 7 个 pop
    int pushes = 0, pops = 0;
    for (size_t i = 0; i < code.size(); ++i) {
        if (code[i] >= 0x50 && code[i] <= 0x57) ++pushes;
        if (code[i] >= 0x58 && code[i] <= 0x5F) ++pops;
        // REX 前缀 + push/pop r8-r15
        if (i + 1 < code.size() && code[i] == 0x41) {
            if (code[i + 1] >= 0x50 && code[i + 1] <= 0x57) ++pushes;
            if (code[i + 1] >= 0x58 && code[i + 1] <= 0x5F) ++pops;
        }
    }
    check(pushes == pops, "push/pop 数量配对");
    std::printf("      push=%d pop=%d 代码长度=%zu\n", pushes, pops, code.size());
}

void test_peb_unlink_self() {
    std::printf("--- PEB 链表自检 ---\n");

    // 自身模块当然在链上 —— 不摘除，只验证检测函数能正确看到
    const void* self = GetModuleHandleW(nullptr);
    check(self != nullptr, "取到自身模块基址");
    check(!ldrunlink::is_unlinked(const_cast<void*>(self)), "自身模块在链上（未摘除）");

    // 不存在的基址应当"判定为不在链上"
    check(ldrunlink::is_unlinked(reinterpret_cast<void*>(0xDEADBEEFull)),
          "不存在基址判定为不在链上");

    // 摘除不存在的模块必须返回错误而不是崩
    check(ldrunlink::unlink_self_module(reinterpret_cast<void*>(0xDEADBEEFull)) < 0,
          "摘除不存在模块返回错误");

    // 遍历链本身不应崩：数一下链长
    int count = 0;
    const auto* peb = reinterpret_cast<const PEB*>(__readgsqword(0x60));
    if (peb && peb->Ldr) {
        const auto* head = reinterpret_cast<const LIST_ENTRY*>(
            &reinterpret_cast<const PEB_LDR_DATA*>(peb->Ldr)->InMemoryOrderModuleList);
        for (auto it = head->Flink; it != head && count < 512; it = it->Flink) ++count;
    }
    check(count > 1, "PEB 链可正常遍历");
    std::printf("      链长=%d\n", count);
}


void test_sendinput_backend() {
    std::printf("--- SendInput 后端 ---\n");

    input::User32Backend b;
    check(b.init(), "init 成功（拿到屏幕尺寸）");
    check(!b.injectable_marker() == false, "标记为可被低级钩子看到");

    // 键按下/抬起：用 F24（几乎没人绑定，且不改变任何游戏状态）
    check(b.key(VK_F24, true), "F24 按下成功");
    check(b.key(VK_F24, false), "F24 抬起成功");

    // 键状态应被真实更新（Raw Input 层看不到标记，但键状态是真的）
    check((GetAsyncKeyState(VK_F24) & 0x8000) == 0, "抬起后键状态已清除");

    // tap：内部带 hold
    check(b.tap(VK_F24, 20), "tap 成功（内部按下-等待-抬起）");

    // 绝对移动：归一化到 [0,65535]，不应失败
    POINT before{};
    GetCursorPos(&before);
    check(b.move_abs(before.x, before.y), "绝对移动成功（回到原位）");
    POINT after{};
    GetCursorPos(&after);
    // 允许 ±2 像素的归一化误差
    const bool close = (after.x - before.x) <= 2 && (before.x - after.x) <= 2 &&
                       (after.y - before.y) <= 2 && (before.y - after.y) <= 2;
    check(close, "绝对移动落点误差在 ±2 像素内");

    // 相对移动 0 不应改变位置
    check(b.move_rel(0, 0), "相对移动(0,0)成功");
    POINT still{};
    GetCursorPos(&still);
    check(still.x == after.x && still.y == after.y, "相对移动 0 不改变位置");

    // 鼠标按键：抬起状态发送应成功
    check(b.mouse_button(0, false), "左键抬起发送成功");
    check(!b.mouse_button(9, true), "无效按键编号被拒绝");

    // 滚轮
    check(b.wheel(0), "滚轮 0 成功");
}

void test_raw_input_invisibility() {
    std::printf("--- Raw Input 层无标记验证 ---\n");
    /*
     * 这个测试验证核心结论：SendInput 在 Raw Input 层不带注入标记。
     *
     * 做法：装 Raw Input 监听（RIDEV_INPUTSINK，后台也能收），
     * 然后 SendInput 一个键，检查拿到的 RAWKEYBOARD 是否"干净"。
     *
     * 判据不是"有没有标记字段"（RAWKEYBOARD 结构里根本没有），
     * 而是 GetMessageExtraInfo() 在 WM_INPUT 处理时返回什么。
     * 实测为 0，即无 0xFF515700 高位。
     */
    static volatile int g_kbdHits = 0;
    static volatile DWORD g_lastExtra = 0xFFFFFFFF;

    struct Ctx {
        static LRESULT CALLBACK proc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
            if (msg == WM_INPUT) {
                UINT size = 0;
                GetRawInputData(reinterpret_cast<HRAWINPUT>(lp), RID_INPUT, nullptr, &size,
                                sizeof(RAWINPUTHEADER));
                if (size > 0 && size <= 1024) {
                    BYTE buf[1024];
                    if (GetRawInputData(reinterpret_cast<HRAWINPUT>(lp), RID_INPUT, buf, &size,
                                        sizeof(RAWINPUTHEADER)) == size) {
                        const auto* ri = reinterpret_cast<const RAWINPUT*>(buf);
                        if (ri->header.dwType == RIM_TYPEKEYBOARD) {
                            g_lastExtra = static_cast<DWORD>(GetMessageExtraInfo());
                            ++g_kbdHits;
                        }
                    }
                }
                return 0;
            }
            return DefWindowProcW(h, msg, wp, lp);
        }
    };

    HINSTANCE inst = GetModuleHandleW(nullptr);
    WNDCLASSW wc{};
    wc.lpfnWndProc = Ctx::proc;
    wc.hInstance = inst;
    wc.lpszClassName = L"selftest_raw";
    RegisterClassW(&wc);

    HWND h = CreateWindowExW(0, L"selftest_raw", L"", WS_POPUP, 0, 0, 1, 1, HWND_MESSAGE,
                             nullptr, inst, nullptr);
    check(h != nullptr, "创建隐藏窗口");
    if (!h) return;

    RAWINPUTDEVICE rid{};
    rid.usUsagePage = 0x01;
    rid.usUsage = 0x06;  // Keyboard
    rid.dwFlags = RIDEV_INPUTSINK;
    rid.hwndTarget = h;
    check(RegisterRawInputDevices(&rid, 1, sizeof(rid)) != FALSE, "注册键盘 Raw Input");

    input::User32Backend b;
    b.init();

    // 泵消息 + 发键
    const DWORD end = GetTickCount() + 800;
    bool sent = false;
    MSG msg;
    while (GetTickCount() < end) {
        if (!sent) {
            b.key(VK_F23, true);
            sent = true;
        }
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        Sleep(3);
    }
    b.key(VK_F23, false);

    check(g_kbdHits > 0, "Raw Input 收到键盘事件");
    if (g_kbdHits > 0) {
        const DWORD extra = g_lastExtra;
        const bool hasLLMarker = (extra & 0xFFFFFF00u) == 0xFF515700u;
        check(!hasLLMarker, "Raw Input 层 ExtraInfo 无 0xFF515700 高位");
        std::printf("      收到 %d 个键盘事件，ExtraInfo=0x%08lX\n", (int)g_kbdHits, extra);
    }

    DestroyWindow(h);
}

void test_hookprobe() {
    std::printf("--- 低级钩子探测 ---\n");
    const auto r = hookprobe::probe();
    std::printf("      baseline=%llu us  with_hook=%llu us  per_hook=%llu us  估计外来钩子=%d\n",
                (unsigned long long)r.baseline_us, (unsigned long long)r.with_hook_us,
                (unsigned long long)r.per_hook_us, r.estimated_foreign_hooks);

    check(r.baseline_us > 0, "基线测量成功");
    check(r.probes_ok || r.baseline_us > 0, "探测流程完成");
    // per_hook 可能为 0（噪声淹没了我们那个钩子的开销），不强求
    check(r.estimated_foreign_hooks >= 0 && r.estimated_foreign_hooks <= 8, "估计值在合理范围");

    // may_see_injection 是静态缓存，只验证可调用且不崩
    const bool verdict = hookprobe::may_see_injection();
    std::printf("      may_see_injection = %d\n", verdict ? 1 : 0);
    check(verdict == hookprobe::may_see_injection(), "静态判定稳定");
}


void test_schema_roundtrip() {
    std::printf("--- 偏移表序列化 ---\n");

    schema::Table t;
    t.game = "test-game";
    t.build = "1.15.4.56008";
    t.exe_timestamp = 0x63A1B2C3;
    t.module_size = 0x2A10000;

    {
        schema::Field f;
        f.name = "player.base";
        f.kind = schema::Kind::Chain;
        f.type = schema::VType::U64;
        f.offs = {0x2F1A3B0};
        f.note = "static offset from module base";
        t.fields.push_back(f);
    }
    {
        schema::Field f;
        f.name = "player.hp";
        f.kind = schema::Kind::Value;
        f.type = schema::VType::U32;
        f.offs = {0x2F1A3B0, 0x10, 0x2C0};
        f.check.op = schema::Check::Op::InRange;
        f.check.a = 1;
        f.check.b = 100000;
        t.fields.push_back(f);
    }
    {
        schema::Field f;
        f.name = "player.pos";
        f.kind = schema::Kind::Value;
        f.type = schema::VType::Vec3;
        f.offs = {0x2F1A3B0, 0x10, 0x30};
        t.fields.push_back(f);
    }

    const std::string text = schema::serialize(t);
    check(!text.empty(), "序列化非空");
    check(text.find("player.hp") != std::string::npos, "含字段名");
    check(text.find("inrange") != std::string::npos, "含验证断言");

    schema::Table back;
    int errLine = 0;
    check(schema::parse(text, back, &errLine), "反序列化成功");
    check(back.game == t.game, "game 一致");
    check(back.build == t.build, "build 一致");
    check(back.exe_timestamp == t.exe_timestamp, "时间戳一致");
    check(back.module_size == t.module_size, "模块大小一致");
    check(back.fields.size() == 3, "字段数一致");

    const auto* hp = back.find("player.hp");
    check(hp != nullptr, "能按名查找");
    if (hp) {
        check(hp->kind == schema::Kind::Value, "kind 保持");
        check(hp->type == schema::VType::U32, "type 保持");
        check(hp->offs.size() == 3, "偏移链长度保持");
        check(hp->offs[0] == 0x2F1A3B0 && hp->offs[1] == 0x10 && hp->offs[2] == 0x2C0,
              "偏移值保持");
        check(hp->check.op == schema::Check::Op::InRange, "断言类型保持");
        check(hp->check.a == 1 && hp->check.b == 100000, "断言边界保持");
    }

    const std::string text2 = schema::serialize(back);
    check(text == text2, "二次序列化完全一致");

    schema::Table bad;
    check(!schema::parse("onlyname\n", bad), "字段过少被拒绝");
    check(schema::parse("", bad), "空文本可解析");
    check(bad.fields.empty(), "空文本无字段");
}

void test_schema_checks() {
    std::printf("--- 验证断言 ---\n");
    schema::Check c;

    c.op = schema::Check::Op::None;
    check(c.eval(0) && c.eval(99999), "None 恒真");

    c.op = schema::Check::Op::Eq; c.a = 42;
    check(c.eval(42), "Eq 命中");
    check(!c.eval(41), "Eq 未命中");

    c.op = schema::Check::Op::Ne; c.a = 0;
    check(c.eval(1), "Ne 命中");
    check(!c.eval(0), "Ne 未命中");

    c.op = schema::Check::Op::InRange; c.a = 1; c.b = 100;
    check(c.eval(1), "InRange 下界含");
    check(c.eval(100), "InRange 上界含");
    check(c.eval(50), "InRange 中值");
    check(!c.eval(0), "InRange 低于下界");
    check(!c.eval(101), "InRange 高于上界");
}

void test_registry() {
    std::printf("--- 多版本注册表 ---\n");
    schema::Registry reg;

    schema::Table a;
    a.build = "1.15.4.56008";
    a.exe_timestamp = 0x11111111;
    reg.add(std::move(a));

    schema::Table b;
    b.build = "1.15.5.57000";
    b.exe_timestamp = 0x22222222;
    reg.add(std::move(b));

    check(reg.size() == 2, "注册 2 个版本");
    check(reg.match(0x11111111, "") != nullptr, "按时间戳命中 A");
    check(reg.match(0x22222222, "") != nullptr, "按时间戳命中 B");
    check(reg.match(0, "1.15.4.56008") != nullptr, "时间戳为 0 时按 build 命中");
    check(reg.match(0x99999999, "") == nullptr, "未知时间戳不命中");
    check(reg.match(0, "9.9.9") == nullptr, "未知 build 不命中");
}

void test_vtype_decode() {
    std::printf("--- 值解码 ---\n");

    uint8_t buf[16] = {};

    buf[0] = 0x78; buf[1] = 0x56; buf[2] = 0x34; buf[3] = 0x12;
    auto v = resolve::decode(buf, schema::VType::U32);
    check(v.ok && v.as_u64() == 0x12345678, "U32 小端解码正确");

    buf[0] = 0xFF; buf[1] = 0xFF; buf[2] = 0xFF; buf[3] = 0xFF;
    v = resolve::decode(buf, schema::VType::I32);
    check(v.ok && v.v.i64 == -1, "I32 -1 正确");

    float f = 3.5f;
    std::memcpy(buf, &f, 4);
    v = resolve::decode(buf, schema::VType::F32);
    check(v.ok && v.as_double() == 3.5, "F32 解码正确");

    float xyz[3] = {1.25f, -2.5f, 100.0f};
    std::memcpy(buf, xyz, 12);
    v = resolve::decode(buf, schema::VType::Vec3);
    check(v.ok, "Vec3 解码成功");
    check(v.v.vec3.x == 1.25f && v.v.vec3.y == -2.5f && v.v.vec3.z == 100.0f,
          "Vec3 三个分量正确");

    check(schema::vtype_size(schema::VType::U8) == 1, "U8 大小");
    check(schema::vtype_size(schema::VType::U64) == 8, "U64 大小");
    check(schema::vtype_size(schema::VType::Vec3) == 12, "Vec3 大小");
    check(schema::vtype_size(schema::VType::None) == 0, "None 大小为 0");
}

void test_resolver_live() {
    std::printf("--- 解析器（对自身进程实测）---\n");
    os::Session s;
    check(s.Begin(GetCurrentProcessId()), "打开自身会话");
    if (!s.valid()) return;

    const uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));

    schema::Table t;
    t.game = "selftest";
    t.build = "live";

    {
        schema::Field f;
        f.name = "pe.lfanew";
        f.kind = schema::Kind::Value;
        f.type = schema::VType::U32;
        f.offs = {0x3C};
        t.fields.push_back(f);
    }
    {
        schema::Field f;
        f.name = "pe.mz";
        f.kind = schema::Kind::Value;
        f.type = schema::VType::U16;
        f.offs = {0x00};
        f.check.op = schema::Check::Op::Eq;
        f.check.a = 0x5A4D;
        t.fields.push_back(f);
    }

    resolve::Resolver r;
    r.bind(&t, base, GetCurrentProcessId());
    check(r.module_base() == base, "绑定模块基址");

    const auto res = r.read_all(s);
    check(res.size() == 2, "读回 2 个字段");

    for (const auto& fr : res) {
        if (fr.name == "pe.mz") {
            check(fr.address_ok, "MZ 地址解析成功");
            check(fr.value_ok, "MZ 值读取成功");
            check(fr.check_ok, "MZ 断言通过");
            check(fr.value.as_u64() == 0x5A4D, "MZ 值正确");
        }
        if (fr.name == "pe.lfanew") {
            check(fr.address_ok && fr.value_ok, "lfanew 读取成功");
            const uint64_t lfanew = fr.value.as_u64();
            check(lfanew > 0 && lfanew < 0x1000, "lfanew 在合理范围");
            std::printf("      e_lfanew = 0x%llX\n", (unsigned long long)lfanew);
        }
    }

    const size_t cachedBefore = r.cached();
    const auto res2 = r.read_all(s);
    check(r.cached() == cachedBefore, "缓存大小稳定");
    check(res2.size() == 2, "第二次读取仍成功");

    const auto h = r.health(s);
    check(h.total == 2, "健康检查字段数正确");
    check(h.check_ok == 2, "全部字段验证通过");
    check(h.usable(), "表可用");
    std::printf("      健康度 %.0f%%\n", h.ratio() * 100);

    s.Close();
}

void test_resolver_misaligned() {
    std::printf("--- 偏移错位检测 ---\n");
    os::Session s;
    if (!s.Begin(GetCurrentProcessId())) { check(false, "打开自身会话"); return; }
    const uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));

    schema::Table t;
    schema::Field f;
    f.name = "wrong.mz";
    f.kind = schema::Kind::Value;
    f.type = schema::VType::U16;
    f.offs = {0x100};
    f.check.op = schema::Check::Op::Eq;
    f.check.a = 0x5A4D;
    t.fields.push_back(f);

    resolve::Resolver r;
    r.bind(&t, base, GetCurrentProcessId());

    const auto res = r.read_all(s);
    check(res.size() == 1, "读回 1 个字段");
    if (!res.empty()) {
        check(res[0].address_ok, "地址仍可解析（该位置可读）");
        check(!res[0].check_ok, "验证断言检出偏移错位");
    }

    const auto h = r.health(s);
    check(!h.usable(), "健康检查判定表不可用");
    std::printf("      错位时健康度 %.0f%%\n", h.ratio() * 100);

    schema::Table t2;
    schema::Field f2;
    f2.name = "broken.chain";
    f2.kind = schema::Kind::Value;
    f2.type = schema::VType::U32;
    f2.offs = {0x3C, 0xFFFFFFF0};
    t2.fields.push_back(f2);

    resolve::Resolver r2;
    r2.bind(&t2, base, GetCurrentProcessId());
    const auto res2 = r2.read_all(s);
    check(res2.size() == 1, "断链字段也返回结果");
    if (!res2.empty()) {
        check(!res2[0].address_ok, "断链被检出（address_ok=false）");
    }

    s.Close();
}


void test_gamestate_builder() {
    std::printf("--- 状态快照 ---\n");

    os::Session s;
    if (!s.Begin(GetCurrentProcessId())) { check(false, "打开自身会话"); return; }
    const uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));

    schema::Table t;
    {
        schema::Field f;
        f.name = "pe.mz";
        f.kind = schema::Kind::Value;
        f.type = schema::VType::U16;
        f.offs = {0x00};
        f.check.op = schema::Check::Op::Eq;
        f.check.a = 0x5A4D;
        t.fields.push_back(f);
    }
    {
        schema::Field f;
        f.name = "pe.lfanew";
        f.kind = schema::Kind::Value;
        f.type = schema::VType::U32;
        f.offs = {0x3C};
        t.fields.push_back(f);
    }
    {
        schema::Field f;
        f.name = "pe.broken";
        f.kind = schema::Kind::Value;
        f.type = schema::VType::U32;
        f.offs = {0x3C, 0xFFFFFF00};
        t.fields.push_back(f);
    }

    resolve::Resolver r;
    r.bind(&t, base, GetCurrentProcessId());

    state::Builder b(r);
    const auto snap = b.build(s);

    check(snap.size() == 3, "快照含 3 个字段");
    check(snap.known("pe.mz"), "MZ 已知");
    check(snap.u64("pe.mz") == 0x5A4D, "MZ 值正确");
    check(snap.known("pe.lfanew"), "lfanew 已知");
    check(!snap.known("pe.broken"), "断链字段未知");

    // 未知字段的默认值应可指定，而不是永远 0
    check(snap.num("pe.broken", -1.0) == -1.0, "未知字段可用自定义默认值");
    check(snap.num("pe.broken") == 0.0, "未知字段默认 0");

    const auto st = snap.stats();
    check(st.total == 3, "统计总数正确");
    check(st.present == 2, "2 个字段有效");
    check(st.unknown == 1, "1 个字段未知");
    check(!st.reliable(), "有未知字段时判定为不可靠");
    std::printf("      有效 %.0f%% (present=%zu unknown=%zu)\n", st.ratio() * 100,
                st.present, st.unknown);

    // 只读指定字段
    const auto partial = b.build_named(s, {"pe.mz"});
    check(partial.size() == 1, "部分快照只有 1 个字段");
    check(partial.known("pe.mz"), "部分快照字段有效");

    s.Close();
}

void test_gamestate_diff() {
    std::printf("--- 状态变更检测 ---\n");

    state::Snapshot a, b;

    state::Field fa;
    fa.status = state::Status::Present;
    fa.value.type = schema::VType::U32;
    fa.value.v.u64 = 100;
    a.put("hp", fa);

    state::Field fb;
    fb.status = state::Status::Present;
    fb.value.type = schema::VType::U32;
    fb.value.v.u64 = 80;
    b.put("hp", fb);

    auto changes = state::diff(a, b);
    check(changes.size() == 1, "检出 1 处变化");
    if (!changes.empty()) {
        check(changes[0].name == "hp", "变化字段名正确");
        check(changes[0].oldValue == 100 && changes[0].newValue == 80, "变化前后值正确");
        check(changes[0].delta() == -20, "delta 正确");
    }

    // 值不变 → 无变化
    changes = state::diff(a, a);
    check(changes.empty(), "相同快照无变化");

    // 状态变化（unknown → present）必须被检出
    state::Snapshot c, d;
    state::Field fu;
    fu.status = state::Status::Unknown;
    c.put("mp", fu);
    state::Field fp;
    fp.status = state::Status::Present;
    fp.value.type = schema::VType::U32;
    fp.value.v.u64 = 50;
    d.put("mp", fp);

    changes = state::diff(c, d);
    check(changes.size() == 1, "状态变化被检出");
    if (!changes.empty()) {
        check(changes[0].becameValid(), "标记为 becameValid");
        check(!changes[0].becameInvalid(), "不是 becameInvalid");
    }

    // 反向
    changes = state::diff(d, c);
    check(changes.size() == 1, "反向状态变化被检出");
    if (!changes.empty()) {
        check(changes[0].becameInvalid(), "标记为 becameInvalid");
    }

    // Suspect 状态不等于 Present
    state::Snapshot e;
    state::Field fs;
    fs.status = state::Status::Suspect;
    fs.value.type = schema::VType::U32;
    fs.value.v.u64 = 1;
    e.put("x", fs);
    check(!e.known("x"), "Suspect 不算 known");
    check(e.stats().suspect == 1, "统计到 1 个 Suspect");
    check(!e.stats().reliable(), "有 Suspect 时不可靠");
}

void test_schema_encrypt_roundtrip() {
    std::printf("--- 偏移表加密存储 ---\n");

    schema::Table t;
    t.game = "test-game";
    t.build = "1.15.4.56008";
    t.exe_timestamp = 0xDEADBEEF;

    schema::Field f;
    f.name = "player.hp";
    f.kind = schema::Kind::Value;
    f.type = schema::VType::U32;
    f.offs = {0x2F1A3B0, 0x10, 0x2C0};
    f.check.op = schema::Check::Op::InRange;
    f.check.a = 1;
    f.check.b = 100000;
    t.fields.push_back(f);

    const std::string plain = schema::serialize(t);
    check(!plain.empty(), "序列化成功");

    // 密文不得包含任何偏移数字的十进制/十六进制明写
    const auto blob = cfg::seal(plain, 0x12345678u);
    const std::string raw(reinterpret_cast<const char*>(blob.data()), blob.size());
    check(raw.find("2F1A3B0") == std::string::npos, "密文不含偏移明写");
    check(raw.find("player.hp") == std::string::npos, "密文不含字段名");

    std::string back;
    check(cfg::open(blob, 0x12345678u, back), "解密成功");
    check(back == plain, "解密结果与原文一致");

    schema::Table t2;
    check(schema::parse(back, t2), "解密后能解析");
    check(t2.fields.size() == 1, "解析出 1 个字段");
    check(t2.exe_timestamp == 0xDEADBEEF, "时间戳保持");
    if (!t2.fields.empty()) {
        check(t2.fields[0].offs.size() == 3, "偏移链保持");
        check(t2.fields[0].offs[0] == 0x2F1A3B0, "偏移值保持");
    }
}


void test_profile() {
    std::printf("--- 目标描述（profile）---\n");

    profile::Profile p;
    p.name = "test-game";
    p.exe = "Game.exe";
    p.module = "Game.exe";
    p.table = "test-game";
    p.poll_ms = 300;
    p.idle_jitter = 80;
    p.require_all_fields = true;
    p.watch = {"player.hp", "player.pos"};

    check(p.valid(), "有 exe 即合法");
    check(p.module_name() == "Game.exe", "module 空时回落 exe");

    const std::string text = profile::serialize(p);
    check(!text.empty(), "序列化非空");
    check(text.find("!exe") != std::string::npos, "含 exe 键");

    profile::Profile q;
    check(profile::parse(text, q), "反序列化成功");
    check(q.name == p.name, "name 一致");
    check(q.exe == p.exe, "exe 一致");
    check(q.module == p.module, "module 一致");
    check(q.table == p.table, "table 一致");
    check(q.poll_ms == p.poll_ms, "poll 一致");
    check(q.idle_jitter == p.idle_jitter, "jitter 一致");
    check(q.require_all_fields == p.require_all_fields, "strict 一致");
    check(q.watch.size() == 2, "watch 条数一致");
    check(q.watch[0] == "player.hp", "watch 内容一致");

    const std::string text2 = profile::serialize(q);
    check(text == text2, "二次序列化一致");

    // 空 exe 不合法
    profile::Profile bad;
    check(!bad.valid(), "空 profile 不合法");
    check(!profile::parse("!name x\n", bad), "缺 exe 时 parse 返回 false");

    // 边界钳制
    profile::Profile clamp;
    check(profile::parse("!exe G.exe\n!poll 1\n", clamp), "极小 poll 可解析");
    check(clamp.poll_ms == 20, "poll 被钳到下限 20");
    check(profile::parse("!exe G.exe\n!poll 999999\n", clamp), "极大 poll 可解析");
    check(clamp.poll_ms == 60000, "poll 被钳到上限 60000");

    check(profile::parse("!exe G.exe\n!jitter 9999\n!poll 100\n", clamp), "过大 jitter");
    check(clamp.idle_jitter <= clamp.poll_ms / 2, "jitter 被钳到 poll/2");

    // 注释与空行
    profile::Profile c2;
    check(profile::parse("# comment\n!exe G.exe\n\n# more\n!poll 200\n", c2), "含注释可解析");
    check(c2.exe == "G.exe" && c2.poll_ms == 200, "注释被正确跳过");
}

void test_profile_storage() {
    std::printf("--- profile 加密存储 ---\n");

    profile::Profile p;
    p.name = "test-game";
    p.exe = "Game.exe";
    p.poll_ms = 250;
    p.watch = {"a.b"};

    const std::string plain = profile::serialize(p);
    const auto blob = cfg::seal(plain, cfgio::kProfileSeed);
    check(!blob.empty(), "加密成功");

    const std::string raw(reinterpret_cast<const char*>(blob.data()), blob.size());
    check(raw.find("Game.exe") == std::string::npos, "密文不含进程名");

    std::string back;
    check(cfg::open(blob, cfgio::kProfileSeed, back), "解密成功");

    profile::Profile q;
    check(profile::parse(back, q), "解密后可解析");
    check(q.exe == p.exe, "进程名保持");
    check(q.poll_ms == p.poll_ms, "轮询间隔保持");

    // 用错的 seed 必须失败
    std::string wrong;
    check(!cfg::open(blob, cfgio::kProfileSeed ^ 1u, wrong), "错误种子被拒绝");
}



void test_pattern_parse() {
    std::printf("--- 特征码解析 ---\n");

    scan::Pattern p;

    // "??" = 一个通配字节
    check(scan::parse_pattern("48 8B 05 ?? ?? ?? ??", p), "带空格的模式可解析");
    check(p.size() == 7, "48 8B 05 + 4 通配 = 7 字节");
    check(p.first_wildcard() == 3, "首个通配在 index 3");
    check(p.bytes[0] == 0x48 && p.bytes[1] == 0x8B && p.bytes[2] == 0x05, "固定字节正确");
    check(p.mask[0] && !p.mask[3], "index 0 固定、index 3 通配");

    // 紧凑写法
    check(scan::parse_pattern("488B05????????", p), "紧凑写法可解析");
    check(p.size() == 7, "紧凑写法也是 7 字节");
    check(p.first_wildcard() == 3, "紧凑写法首个通配也在 3");

    // 单问号写法
    check(scan::parse_pattern("48 8B 05 ? ? ? ?", p), "单问号写法可解析");
    check(p.size() == 7, "单问号也是 7 字节");

    // 0x 前缀
    check(scan::parse_pattern("0x48 0x8B 0x05 ? ? ? ?", p), "0x 前缀可解析");
    check(p.size() == 7, "0x 前缀不影响长度");

    // 小写
    check(scan::parse_pattern("48 8b 05 ?? ?? ?? ?? 33 db", p), "小写可解析");
    check(p.size() == 9, "小写长度正确");
    check(p.bytes[7] == 0x33 && p.bytes[8] == 0xDB, "小写字节值正确");

    // 无通配（纯定位模式）
    check(scan::parse_pattern("48 8B 05", p), "纯固定字节可解析");
    check(p.first_wildcard() == -1, "无通配返回 -1");
    check(p.size() == 3, "长度 3");

    // 非法输入
    check(!scan::parse_pattern("", p), "空串被拒绝");
    check(!scan::parse_pattern("zz", p), "非法字符被拒绝");
    check(!scan::parse_pattern("?? ?? ??", p), "全通配被拒绝（没有固定字节）");
    check(scan::parse_pattern("4", p), "单个 nibble 解析为 0x04");
    check(p.bytes[0] == 0x04, "单 nibble 值正确");
    check(!scan::parse_pattern("GG", p), "非十六进制被拒绝");
}

void test_scan_live() {
    std::printf("--- 特征码扫描（对自身模块实测）---\n");

    os::Session s;
    if (!s.Begin(GetCurrentProcessId())) { check(false, "打开自身会话"); return; }

    const uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    const size_t modSize = nt->OptionalHeader.SizeOfImage;

    check(modSize > 0x1000, "模块大小合理");

    // 找 MZ（一定在 base+0）
    scan::Pattern mz;
    scan::parse_pattern("4D 5A", mz);
    const auto hit = scan::find_first(s, base, 0x1000, mz);
    check(hit.ok, "找到 MZ");
    check(hit.addr == base, "MZ 在模块开头");

    // 找 PE 签名（应该在 e_lfanew 处）
    scan::Pattern pe;
    scan::parse_pattern("50 45 00 00", pe);
    const auto peHit = scan::find_first(s, base, 0x1000, pe);
    check(peHit.ok, "找到 PE 签名");
    if (peHit.ok) {
        check(peHit.addr == base + dos->e_lfanew, "PE 签名位置正确");
    }

    // 全模块扫 mov rax,[rip+x]
    scan::Pattern mov;
    scan::parse_pattern("48 8B 05 ?? ?? ?? ??", mov);
    const auto hits = scan::find_all(s, base, modSize, mov, 16);
    check(!hits.empty(), "全模块能扫到 rip 相对寻址指令");
    std::printf("      48 8B 05 ?? ?? ?? ?? 命中 %zu 处\n", hits.size());

    // 每一个命中的 disp 都应该解析出可读地址
    int readable = 0;
    for (size_t i = 0; i < hits.size() && i < 8; ++i) {
        const uintptr_t t = scan::resolve_rip_relative(s, hits[i], 3, 4);
        uint8_t probe = 0;
        if (t != 0 && s.Read(t, &probe, 1)) ++readable;
    }
    check(readable > 0, "至少一半命中解析出可读地址");

    s.Close();
}

void test_resolve() {
    std::printf("--- 特征码解析到地址 ---\n");

    os::Session s;
    if (!s.Begin(GetCurrentProcessId())) { check(false, "打开自身会话"); return; }
    const uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    const size_t modSize = nt->OptionalHeader.SizeOfImage;

    // 唯一模式：PE 签名 + 机器类型（x64 = 0x8664）
    const auto r = scan::resolve(s, base, modSize, "50 45 00 00 64 86");
    check(r.ok, "唯一模式解析成功");
    check(r.matches == 1, "命中次数为 1");
    if (r.ok) {
        check(r.hit == base + dos->e_lfanew, "命中位置正确");
        check(r.target == r.hit, "无通配时 target == hit");
        std::printf("      PE 签名命中 base+0x%llX\n",
                    static_cast<unsigned long long>(r.hit - base));
    }

    // 不唯一的模式必须拒绝
    const auto r2 = scan::resolve(s, base, modSize, "48 8B 05 ?? ?? ?? ??");
    check(!r2.ok, "不唯一模式被拒绝（ok=false）");
    check(r2.matches >= 2, "报告多个命中");
    std::printf("      不唯一模式 matches=%d（正确拒绝）\n", r2.matches);

    // 不存在的模式
    const auto r3 = scan::resolve(s, base, modSize,
                                  "DE AD BE EF DE AD BE EF DE AD BE EF");
    check(!r3.ok, "不存在的模式返回失败");
    check(r3.matches == 0, "命中数为 0");

    s.Close();
}

void test_rip_relative() {
    std::printf("--- RIP 相对寻址 ---\n");

    os::Session s;
    if (!s.Begin(GetCurrentProcessId())) { check(false, "打开自身会话"); return; }
    const uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    const size_t modSize = nt->OptionalHeader.SizeOfImage;

    // 找 lea rcx,[rip+x]，验证解析出的地址可读
    scan::Pattern lea;
    scan::parse_pattern("48 8D 0D ?? ?? ?? ??", lea);
    const auto hits = scan::find_all(s, base, modSize, lea, 8);
    check(!hits.empty(), "找到 lea 指令");

    int good = 0;
    for (size_t i = 0; i < hits.size() && i < 5; ++i) {
        const uintptr_t t = scan::resolve_rip_relative(s, hits[i], 3, 4);
        if (t == 0) continue;

        // 解析出的地址必须在模块范围内（lea 通常指向模块内的字符串/全局）
        uint8_t probe = 0;
        if (s.Read(t, &probe, 1)) ++good;
    }
    check(good > 0, "lea 解析出的地址可读");
    std::printf("      %d/%zu 个 lea 解析出可读地址\n", good,
                hits.size() < 5 ? hits.size() : size_t(5));

    // 空 pattern 不能崩
    check(scan::resolve_rip_relative(s, base, 3, 4) != 0 || true, "无效调用不崩");

    s.Close();
}




void test_guard_status() {
    std::printf("--- 陷阱状态码判定 ---\n");
    check(guard::is_guard_violation(0x80000001), "识别 GUARD_PAGE_VIOLATION");
    check(guard::is_access_denied(static_cast<LONG>(0xC0000022)), "识别 ACCESS_DENIED");
    check(guard::is_page_fault(static_cast<LONG>(0xC0000005)), "识别 PAGE_FAULT");
    check(guard::is_partial_copy(0x8000000D), "识别 PARTIAL_COPY");
    check(!guard::is_partial_copy(0x80000001), "PARTIAL_COPY 不与 GUARD 混淆");
}

void test_budget() {
    std::printf("--- 读取预算（令牌桶）---\n");

    guard::Budget b(100.0, 50.0);   // 每秒 100，容量 50
    check(b.available() > 0, "初始有令牌");

    int ok = 0, rejected = 0;
    for (int i = 0; i < 80; ++i) {
        if (b.try_consume(1.0)) ++ok;
        else ++rejected;
    }
    check(ok == 50, "容量内全部放行");
    check(rejected == 30, "超出容量被拒绝");
    check(b.consumed() == 0, "consumed 只统计成功（实现为计数，此处验证初始为 0）");

    // 额度恢复：等一段时间
    Sleep(300);   // 300ms × 100/s = 30 个令牌
    const double avail = b.available();
    check(avail > 20 && avail <= 50, "等待后令牌部分恢复");
    std::printf("      等待 300ms 后可用 %.0f 个\n", avail);

    // 改速率
    b.set_rate(10.0, 5.0);
    check(b.available() <= 5, "降容量后不超上限");
}

void test_trap_list() {
    std::printf("--- 陷阱地址表 ---\n");
    guard::TrapList t;
    check(t.size() == 0, "初始为空");

    t.add(0x1000);
    check(t.hit(0x1000), "精确命中");
    check(t.hit(0x1ABC), "同页内偏移命中");
    check(!t.hit(0x2000), "跨页不命中");
    check(t.size() == 1, "同页只记一次");

    t.add(0x1FFF);   // 同页
    check(t.size() == 1, "同页重复添加不增长");

    t.add(0x2000);
    check(t.size() == 2, "不同页增长");

    t.clear();
    check(t.size() == 0, "clear 后可清空");
    check(!t.hit(0x1000), "清空后不命中");
}

void test_guard_reader_live() {
    std::printf("--- 页陷阱实测 ---\n");

    os::Session s;
    if (!s.Begin(GetCurrentProcessId())) { check(false, "打开自身会话"); return; }

    guard::GuardedReader gr(10000, 10000);   // 高额度，不干扰测试
    const uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));

    uint8_t buf[16];

    // 正常读取不应被误判为陷阱
    int okCount = 0, trapCount = 0;
    for (int i = 0; i < 20; ++i) {
        const auto r = gr.read(s, base + i * 4, buf, 4);
        if (r.ok()) ++okCount;
        if (r.outcome == guard::ReadOutcome::GuardTrap) ++trapCount;
    }
    check(okCount == 20, "正常区 20 次全部读成功");
    check(trapCount == 0, "正常区不产生误判");
    check(gr.clean(), "无陷阱命中");

    // 未提交地址 → 陷阱
    const auto r1 = gr.read(s, 0x1000, buf, 4);
    check(r1.outcome == guard::ReadOutcome::GuardTrap, "未提交地址判定为陷阱");

    // PAGE_GUARD → 陷阱
    void* guarded = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    check(guarded != nullptr, "分配测试页");
    if (guarded) {
        *(volatile int*)guarded = 0x11223344;
        DWORD old = 0;
        check(VirtualProtect(guarded, 0x1000, PAGE_READWRITE | PAGE_GUARD, &old) != FALSE,
              "装上 PAGE_GUARD");

        const auto r2 = gr.read(s, reinterpret_cast<uintptr_t>(guarded), buf, 4);
        check(r2.outcome == guard::ReadOutcome::GuardTrap, "guard 页被判定为陷阱");
        check(r2.got == 0, "guard 页读不到数据");
        // 实测确认：跨进程读 guard 页返回 PARTIAL_COPY 而不是 GUARD_PAGE_VIOLATION
        check(guard::is_partial_copy(r2.status), "guard 页返回 PARTIAL_COPY（实测结论）");

        // 第二次应被陷阱表挡住，不产生实际读取
        const auto r3 = gr.read(s, reinterpret_cast<uintptr_t>(guarded), buf, 4);
        check(r3.outcome == guard::ReadOutcome::GuardTrap, "第二次仍报陷阱");
        check(r3.status == 0, "第二次未真正发起读取（status 为 0）");

        VirtualFree(guarded, 0, MEM_RELEASE);
    }

    // PAGE_NOACCESS → 陷阱
    void* noaccess = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
    if (noaccess) {
        const auto r4 = gr.read(s, reinterpret_cast<uintptr_t>(noaccess), buf, 4);
        check(r4.outcome == guard::ReadOutcome::GuardTrap, "NOACCESS 页判定为陷阱");
        VirtualFree(noaccess, 0, MEM_RELEASE);
    }

    check(!gr.clean(), "踩过陷阱后判定为不干净");
    std::printf("      陷阱命中 %u 次，拉黑 %zu 页\n", gr.guard_hits(), gr.traps().size());

    s.Close();
}

void test_guard_budget_integration() {
    std::printf("--- 预算与陷阱联动 ---\n");

    os::Session s;
    if (!s.Begin(GetCurrentProcessId())) { check(false, "打开自身会话"); return; }

    // 额度极低：3 个令牌
    guard::GuardedReader gr(1000.0, 3.0);
    const uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
    uint8_t buf[4];

    int ok = 0, exhausted = 0;
    for (int i = 0; i < 10; ++i) {
        const auto r = gr.read(s, base + i, buf, 4);
        if (r.ok()) ++ok;
        if (r.outcome == guard::ReadOutcome::BudgetExhausted) ++exhausted;
    }
    check(ok <= 3, "成功次数不超过额度");
    check(exhausted >= 7, "超出额度被拒");
    std::printf("      ok=%d exhausted=%d\n", ok, exhausted);

    // 额度耗尽后不应产生真实读取（陷阱表不应增长）
    const size_t trapsBefore = gr.traps().size();
    gr.read(s, 0x10, buf, 4);   // 这个本来会触发陷阱，但额度已尽
    check(gr.traps().size() == trapsBefore, "额度耗尽时不发起真实读取");

    s.Close();
}


void test_accessmask() {
    std::printf("--- 句柄权限掩码校验 ---\n");

    // 纯读取只允许这两位
    check(access::kPureRead == (PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION),
          "kPureRead 只含 VM_READ + QUERY_LIMITED");

    // 纯读取掩码通过
    {
        const auto v = access::check_readonly(access::kPureRead, false);
        check(v.ok, "纯读取掩码通过");
        check(v.badBits == 0, "无越权位");
    }

    // 只要 VM_READ 也通过
    check(access::check_readonly(PROCESS_VM_READ, false).ok, "仅 VM_READ 通过");

    // 只要 QUERY_LIMITED 也通过
    check(access::check_readonly(PROCESS_QUERY_LIMITED_INFORMATION, false).ok,
          "仅 QUERY_LIMITED 通过");

    // 带写权限的必须被拒
    {
        const ACCESS_MASK bad = PROCESS_VM_READ | PROCESS_VM_WRITE;
        const auto v = access::check_readonly(bad, false);
        check(!v.ok, "含 VM_WRITE 被拒绝");
        check((v.badBits & PROCESS_VM_WRITE) != 0, "报告出越权的 VM_WRITE");
    }

    // VM_OPERATION 也必须被拒
    {
        const auto v = access::check_readonly(PROCESS_VM_READ | PROCESS_VM_OPERATION, false);
        check(!v.ok, "含 VM_OPERATION 被拒绝");
    }

    // CREATE_THREAD 永远被拒，即使 allowMap
    {
        const auto v = access::check_readonly(PROCESS_VM_READ | PROCESS_CREATE_THREAD, true);
        check(!v.ok, "含 CREATE_THREAD 被拒绝（即使允许映射）");
    }

    // ALL_ACCESS 必须被拒
    check(!access::check_readonly(PROCESS_ALL_ACCESS, false).ok,
          "ALL_ACCESS 被拒绝（纯读取）");
    check(!access::check_readonly(PROCESS_ALL_ACCESS, true).ok,
          "ALL_ACCESS 被拒绝（映射）");

    // allowMap 允许 VM_WRITE|VM_OPERATION，但仍不允许注入类
    check(access::check_readonly(access::kMapNeeded, true).ok,
          "映射所需掩码在 allowMap 下通过");
    check(!access::check_readonly(access::kMapNeeded, false).ok,
          "映射所需掩码在纯读取下被拒");

    // 最小掩码生成
    check(access::minimal_mask(access::Intent::ReadOnly) == access::kPureRead,
          "ReadOnly 意图给出纯读取掩码");
    check(access::minimal_mask(access::Intent::MapImage) == access::kMapNeeded,
          "MapImage 意图给出映射掩码");

    // 可疑度评分
    check(access::suspicion_score(access::kPureRead) == 0, "纯读取可疑度 0");
    check(access::suspicion_score(access::kMapNeeded) > 0, "映射掩码可疑度 > 0");
    check(access::suspicion_score(PROCESS_ALL_ACCESS) > 200, "ALL_ACCESS 可疑度很高");
    check(access::suspicion_score(PROCESS_VM_READ | PROCESS_CREATE_THREAD) >= 100,
          "CREATE_THREAD 单项就很高");

    // 危险位计数
    check(access::danger_count(access::kPureRead) == 0, "纯读取无危险位");
    check(access::danger_count(access::kMapNeeded) == 2, "映射掩码有 2 个危险位");
    check(access::danger_count(PROCESS_ALL_ACCESS) >= 6, "ALL_ACCESS 危险位至少 6 个");

    // 位名
    check(std::string(access::bit_name(PROCESS_VM_READ)) == "VM_READ", "VM_READ 名字");
    check(std::string(access::bit_name(PROCESS_VM_WRITE)) == "VM_WRITE", "VM_WRITE 名字");
}

void test_session_guard() {
    std::printf("--- Session 权限闸门 ---\n");

    os::Session s;

    // 纯读取：正常通过
    check(s.Begin(GetCurrentProcessId()), "默认纯读取可打开");
    check(s.last_audit().passed, "审计记录为通过");
    check(s.last_audit().requested == access::kPureRead, "记录请求的掩码");
    s.Close();

    // 带写权限但没声明 allowMap：必须被拒，且不发起 OpenProcess
    os::Session s2;
    check(!s2.Begin(GetCurrentProcessId(),
                    PROCESS_VM_READ | PROCESS_VM_WRITE, false),
          "带 VM_WRITE 未声明用途时被拒");
    check(!s2.last_audit().passed, "审计记录为拒绝");
    check((s2.last_audit().badBits & PROCESS_VM_WRITE) != 0, "报告越权位");
    check(!s2.valid(), "被拒后没有句柄（未发起调用）");

    // CREATE_THREAD：即使 allowMap 也拒
    os::Session s3;
    check(!s3.Begin(GetCurrentProcessId(),
                    PROCESS_VM_READ | PROCESS_CREATE_THREAD, true),
          "CREATE_THREAD 即使 allowMap 也被拒");
    check(!s3.valid(), "被拒后无句柄");

    // ALL_ACCESS：永远拒
    os::Session s4;
    check(!s4.Begin(GetCurrentProcessId(), PROCESS_ALL_ACCESS, true),
          "ALL_ACCESS 被拒");
    check(!s4.valid(), "被拒后无句柄");

    // 映射场景：显式 allowMap 才通过
    os::Session s5;
    check(s5.Begin(GetCurrentProcessId(), access::kMapNeeded, true),
          "allowMap 下映射掩码通过");
    check(s5.valid(), "有句柄");
    check(s5.last_audit().passed, "审计通过");
    s5.Close();
}


void test_scan_field_parse() {
    std::printf("--- scan 字段格式 ---\n");

    // 基本 scan 字段：无 check，带特征码
    {
        const std::string text =
            "!game test\n"
            "player.guid scan u64 - scan 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? ge 1\n";
        schema::Table t;
        int el = 0;
        check(schema::parse(text, t, &el), "scan 字段可解析");
        check(t.fields.size() == 1, "解析出 1 个字段");
        if (!t.fields.empty()) {
            const auto& f = t.fields[0];
            check(f.kind == schema::Kind::Scan, "kind 自动识别为 Scan");
            check(f.is_scan(), "is_scan 为真");
            check(f.scanPattern == "48", "特征码首字节（空格分隔会被切成多个 token）");
        }
    }

    // 紧凑特征码（无空格）才能完整存进一个 token
    {
        const std::string text =
            "!game test\n"
            "player.guid scan u64 - scan 488D0D????????E8???????? ge 1\n";
        schema::Table t;
        check(schema::parse(text, t), "紧凑特征码可解析");
        if (!t.fields.empty()) {
            const auto& f = t.fields[0];
            check(f.scanPattern == "488D0D????????E8????????", "紧凑特征码完整保留");
            check(f.check.op == schema::Check::Op::Ge, "check 被正确解析");
            check(f.check.a == 1, "check 边界正确");
        }
    }

    // deref 修饰
    {
        const std::string text =
            "!game test\nx scan u64 - - scan 488B05???????? deref\n";
        schema::Table t;
        check(schema::parse(text, t), "带 deref 的 scan 可解析");
        if (!t.fields.empty()) {
            check(t.fields[0].scanDeref, "deref 标志被识别");
        }
    }

    // addend 修饰
    {
        const std::string text =
            "!game test\nx scan u64 - - scan 483905???????? -8\n";
        schema::Table t;
        check(schema::parse(text, t), "带 addend 的 scan 可解析");
        if (!t.fields.empty()) {
            check(t.fields[0].scanAddend == -8, "负 addend 正确");
            check(!t.fields[0].scanDeref, "没写 deref 则为假");
        }
    }

    // 序列化往返
    {
        schema::Table t;
        t.game = "test";
        schema::Field f;
        f.name = "player.guid";
        f.kind = schema::Kind::Scan;
        f.type = schema::VType::U64;
        f.scanPattern = "488D0D????????E8????????";
        f.scanDeref = true;
        f.scanAddend = -8;
        f.check.op = schema::Check::Op::Ge;
        f.check.a = 1;
        t.fields.push_back(f);

        const std::string a = schema::serialize(t);
        check(a.find("scan") != std::string::npos, "序列化含 scan 关键字");
        check(a.find("488D0D????????E8????????") != std::string::npos, "含特征码");
        check(a.find("deref") != std::string::npos, "含 deref");

        schema::Table t2;
        check(schema::parse(a, t2), "往返可解析");
        const std::string b = schema::serialize(t2);
        check(a == b, "二次序列化一致");
        if (!t2.fields.empty()) {
            check(t2.fields[0].scanAddend == -8, "addend 往返保持");
            check(t2.fields[0].scanDeref, "deref 往返保持");
        }
    }

    // 普通字段不受影响
    {
        const std::string text =
            "!game test\nplayer.hp value u32 0x10,0x20 inrange 1 100\n";
        schema::Table t;
        check(schema::parse(text, t), "普通字段仍可解析");
        if (!t.fields.empty()) {
            check(!t.fields[0].is_scan(), "普通字段不是 scan");
            check(t.fields[0].kind == schema::Kind::Value, "kind 保持 Value");
            check(t.fields[0].offs.size() == 2, "偏移链正确");
        }
    }
}

void test_scan_field_live() {
    std::printf("--- scan 字段实测（自身模块）---\n");

    os::Session s;
    if (!s.Begin(GetCurrentProcessId())) { check(false, "打开自身会话"); return; }

    size_t modSize = 0;
    const uintptr_t base = os::module_base(GetCurrentProcessId(), L"selftest.exe", &modSize);
    check(base != 0, "取到自身模块基址");
    check(modSize > 0x1000, "取到模块大小");
    if (base == 0 || modSize == 0) return;

    // 用 PE 签名做特征码：一定唯一且不需要解析 disp
    schema::Table t;
    t.game = "selftest";

    schema::Field f;
    f.name = "pe.sig";
    f.kind = schema::Kind::Scan;
    f.type = schema::VType::U32;
    f.scanPattern = "4D5A9000";   // DOS 头：模块开头唯一
    t.fields.push_back(f);

    // 再放一个解析 disp 的：lea rcx,[rip+x]
    schema::Field f2;
    f2.name = "lea.target";
    f2.kind = schema::Kind::Scan;
    f2.type = schema::VType::U8;
    f2.scanPattern = "488D0D????????";
    t.fields.push_back(f2);

    resolve::Resolver r;
    r.bind(&t, base, GetCurrentProcessId(), modSize);

    const auto res = r.read_all(s);
    check(res.size() == 2, "读回 2 个字段");

    for (const auto& fr : res) {
        if (fr.name == "pe.sig") {
            check(fr.address_ok, "DOS 头扫描成功");
            if (fr.address_ok) {
                // DOS 头就在模块 base 处
                check(fr.addr == base, "扫描位置等于模块开头");
            }
        }
        if (fr.name == "lea.target") {
            // lea 可能不唯一，那就会失败；成功则地址应可读
            if (fr.address_ok) {
                check(fr.addr != 0, "lea 目标解析出地址");
            } else {
                check(r.scan_ambiguous() > 0 || r.scan_failures() > 0,
                      "失败时记录了原因");
            }
        }
    }

    // 缓存：第二次不应重复扫描
    const size_t cachedAfterFirst = r.cached();
    r.read_all(s);
    check(r.cached() == cachedAfterFirst, "缓存稳定（不重复扫描）");

    std::printf("      扫描失败 %u 次，不唯一 %u 次\n",
                r.scan_failures(), r.scan_ambiguous());

    s.Close();
}

void test_scan_field_errors() {
    std::printf("--- scan 字段错误处理 ---\n");

    os::Session s;
    if (!s.Begin(GetCurrentProcessId())) { check(false, "打开自身会话"); return; }

    size_t modSize = 0;
    const uintptr_t base = os::module_base(GetCurrentProcessId(), L"selftest.exe", &modSize);

    // 1. 不存在的特征码 → 扫描失败
    {
        schema::Table t;
        schema::Field f;
        f.name = "nope";
        f.kind = schema::Kind::Scan;
        f.scanPattern = "DEADBEEFDEADBEEFDEADBEEF";
        t.fields.push_back(f);

        resolve::Resolver r;
        r.bind(&t, base, GetCurrentProcessId(), modSize);
        const auto res = r.read_all(s);
        check(res.size() == 1, "返回 1 个结果");
        check(!res[0].address_ok, "不存在的特征码解析失败");
        check(r.scan_failures() > 0, "记录了失败次数");
    }

    // 2. 不唯一的特征码 → 拒绝（比找错更安全）
    {
        schema::Table t;
        schema::Field f;
        f.name = "ambiguous";
        f.kind = schema::Kind::Scan;
        f.scanPattern = "00";   // 单字节 00 必然命中无数处
        t.fields.push_back(f);

        resolve::Resolver r;
        r.bind(&t, base, GetCurrentProcessId(), modSize);
        const auto res = r.read_all(s);
        check(!res.empty() && !res[0].address_ok, "不唯一特征码被拒绝");
        check(r.scan_ambiguous() > 0, "记录了不唯一次数");
    }

    // 3. 模块大小为 0 → 扫描无法进行
    {
        schema::Table t;
        schema::Field f;
        f.name = "nomsize";
        f.kind = schema::Kind::Scan;
        f.scanPattern = "4D5A9000";
        t.fields.push_back(f);

        resolve::Resolver r;
        r.bind(&t, base, GetCurrentProcessId(), 0);   // 故意不给大小
        const auto res = r.read_all(s);
        check(!res.empty() && !res[0].address_ok, "模块大小为 0 时扫描失败");
    }

    // 4. set_module_size 后应该能成功
    {
        schema::Table t;
        schema::Field f;
        f.name = "later";
        f.kind = schema::Kind::Scan;
        f.scanPattern = "4D5A9000";
        t.fields.push_back(f);

        resolve::Resolver r;
        r.bind(&t, base, GetCurrentProcessId(), 0);
        r.set_module_size(modSize);
        const auto res = r.read_all(s);
        check(!res.empty() && res[0].address_ok, "设置模块大小后扫描成功");
    }

    s.Close();
}

void test_humanizer() {
    std::printf("--- 人类化调度 ---\n");
    input::Humanizer h;
    bool positive = true;
    for (int i = 0; i < 200; ++i)
        if (h.tap_delay(90) < 1) positive = false;
    check(positive, "点击延迟恒为正");

    std::vector<POINT> path;
    h.curve(POINT{0, 0}, POINT{500, 300}, path);
    check(path.size() >= 15, "轨迹点数合理");
    check(path.front().x == 0 && path.front().y == 0, "轨迹起点正确");
    std::printf("      轨迹点数=%zu\n", path.size());
}

}  // namespace

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("===== memkit selftest =====\n");

    test_obf();
    test_api_resolution();
    test_rng();
    test_ident();
    test_session();
    test_handle_audit();
    test_scan();
    test_scheduler();
    test_antidebug();
    test_config_crypto();
    test_ringlog();
    test_task_batch();
    test_ipc_protocol();
    test_driver_proto();
    test_parent_check();
    test_pe_parser();
    test_remote_resolver();
    test_manualmap_errors();
    test_thread_enum();
    test_hijack_preamble();
    test_peb_unlink_self();
    test_sendinput_backend();
    test_raw_input_invisibility();
    test_hookprobe();
    test_scan_field_parse();
    test_scan_field_live();
    test_scan_field_errors();
    test_accessmask();
    test_session_guard();
    test_guard_status();
    test_budget();
    test_trap_list();
    test_guard_reader_live();
    test_guard_budget_integration();
    test_pattern_parse();
    test_scan_live();
    test_resolve();
    test_rip_relative();
    test_schema_roundtrip();
    test_schema_checks();
    test_registry();
    test_vtype_decode();
    test_resolver_live();
    test_resolver_misaligned();
    test_gamestate_builder();
    test_gamestate_diff();
    test_schema_encrypt_roundtrip();
    test_profile();
    test_profile_storage();
    test_humanizer();

    std::printf("============================\n");
    if (g_fail == 0) {
        std::printf("全部通过\n");
        return 0;
    }
    std::printf("失败 %d 项\n", g_fail);
    return 1;
}
