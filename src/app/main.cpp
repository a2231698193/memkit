// app/main.cpp —— 装配层（游戏无关）
//
// 这个文件不认识任何具体游戏。目标进程、模块、偏移表、轮询间隔
// 全部来自加密的 profile 文件（见 os/profile.hpp）。
//
// 当前阶段：框架完整，等待真实偏移表。
// 没有任何业务逻辑，只做：
//   1. 启动自查
//   2. 加载偏移表（加密文件）
//   3. 定位目标进程
//   4. 按固定节拍读快照并记录健康度
//
// 真实偏移表到位后，只需要在 loop 里加业务判断，不用改这一层的结构。
#include <windows.h>

#include <memory>
#include <string>
#include <vector>

#include "common/cfg.hpp"
#include "common/obf.hpp"
#include "common/ringlog.hpp"
#include "common/rnd.hpp"
#include "input/backend.hpp"
#include "input/driver.hpp"
#include "input/hookprobe.hpp"
#include "input/u32.hpp"
#include "os/config_io.hpp"
#include "os/gamestate.hpp"
#include "os/profile.hpp"
#include "os/handles.hpp"
#include "os/process.hpp"
#include "os/resolve.hpp"
#include "os/scan.hpp"
#include "os/sched.hpp"
#include "os/schema.hpp"
#include "stealth/antidebug.hpp"
#include "stealth/ident.hpp"
#include "stealth/manifest.hpp"

namespace {

// 宽字符转换：profile 里存的是 UTF-8，系统 API 要 UTF-16
// 不用 MultiByteToWideChar 是为了避免额外导入（自实现够用：全是 ASCII 进程名）
std::wstring widen(const std::string& s) {
    std::wstring out;
    out.reserve(s.size());
    for (unsigned char c : s) out.push_back(static_cast<wchar_t>(c));
    return out;
}

}  // namespace

int wmain() {
    rlog::Ring::instance().reset(os::ticks());

    // ---------- 1. 自查 ----------
    if (!stealth::gate()) return 0;
    RLOG(Info, rlog::kEvBoot, 1, GetCurrentProcessId());

    // ---------- 2. 单实例 ----------
    const std::wstring mtxName = L"Global\\" + stealth::instance_id();
    HANDLE once = CreateMutexW(nullptr, TRUE, mtxName.c_str());
    if (!once) return 0;
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(once);
        return 0;
    }

    // ---------- 3. 输入后端 ----------
    input::User32Backend u32Backend;
    const bool u32Ready = u32Backend.init();

    const bool maySeeMark = hookprobe::may_see_injection();
    RLOG(Info, rlog::kEvBackendSelect, 1, maySeeMark ? 1u : 0u);

    input::DriverBackend driverBackend;
    bool driverReady = false;
    input::IBackend* backend = &u32Backend;
    if (maySeeMark) {
        driverReady = driverBackend.init();
        if (driverReady) backend = &driverBackend;
    }
    RLOG(Info, rlog::kEvBackendSelect, 3, driverReady ? 1u : 0u, u32Ready ? 1u : 0u,
         maySeeMark ? 1u : 0u);

    // ---------- 4. profile + 偏移表 ----------
    cfgio::Paths paths;
    if (!paths.init()) {
        RLOG(Error, rlog::kEvConfigTampered);
        if (once) CloseHandle(once);
        return 0;
    }

    // profile 决定"打哪个游戏"；没有 profile 就什么都不做
    profile::Profile prof;
    {
        std::string text;
        if (!cfgio::read_encrypted(paths.profile_path(), cfgio::kProfileSeed, text) ||
            !profile::parse(text, prof)) {
            RLOG(Warn, rlog::kEvConfigOpened, 1, 0);
            if (once) CloseHandle(once);
            return 0;
        }
    }
    RLOG(Info, rlog::kEvConfigOpened, 2, prof.name.size());

    schema::Registry reg;
    const size_t loaded = cfgio::load_all(paths, reg);
    RLOG(Info, rlog::kEvConfigOpened, 3, loaded);

    // 选表：profile 指定了 table 标识就按它匹配
    const schema::Table* chosen = nullptr;
    for (const auto& t : reg.all()) {
        if (!prof.table.empty() && t.game == prof.table) { chosen = &t; break; }
    }
    if (!chosen && reg.size() > 0) chosen = &reg.all().front();
    if (!chosen) {
        RLOG(Warn, rlog::kEvConfigOpened, 4, 0);
    }

    const std::wstring targetExe = widen(prof.exe);
    const std::wstring targetMod = widen(prof.module_name());

    // ---------- 5. 主循环 ----------
    input::Humanizer human;

    // 会话调度器：按 pid 构造，缓存上次 pid 避免重复构造
    DWORD boundPid = 0;
    uintptr_t moduleBase = 0;
    const schema::Table* activeTable = nullptr;
    resolve::Resolver resolver;
    std::unique_ptr<state::Builder> builder;

    state::Snapshot prevSnap;
    bool hasPrev = false;

    bool running = true;
    uint32_t loop = 0;
    bool targetSeen = false;

    while (running) {
        Sleep(static_cast<DWORD>(human.idle_gap(prof.poll_ms)));
        human.on_idle();

        const auto pids = os::find_pid(targetExe);
        if (pids.empty()) {
            if (targetSeen) {
                RLOG(Info, rlog::kEvTargetLost);
                targetSeen = false;
                boundPid = 0;
                moduleBase = 0;
                activeTable = nullptr;
                builder.reset();
                hasPrev = false;
            }
            if (++loop > 5000) running = false;
            continue;
        }

        const DWORD pid = pids.front();

        // 进程换了 / 第一次见：重新绑定
        if (pid != boundPid) {
            boundPid = pid;
            targetSeen = true;
            RLOG(Info, rlog::kEvTargetFound, 1, pid);

            moduleBase = os::module_base(pid, targetMod);
            if (moduleBase != 0 && chosen) {
                activeTable = chosen;
                resolver.bind(activeTable, moduleBase, pid);
                builder = std::make_unique<state::Builder>(resolver);
            }
            RLOG(Trace, rlog::kEvTargetFound, 2, moduleBase,
                 activeTable ? activeTable->fields.size() : 0u);
        }

        if (moduleBase != 0 && builder) {
            os::Scheduler sched(pid);

            // 一个批次内读所有关注的字段
            bool readOk = false;
            state::Snapshot snap;
            sched.run_batch([&](os::Session& s) {
                if (prof.watch.empty()) {
                    snap = builder->build(s);
                } else {
                    snap = builder->build_named(s, prof.watch);
                }
                readOk = true;
                return true;
            });

            if (readOk) {
                const auto st = snap.stats();
                if (!st.reliable()) {
                    RLOG(Trace, rlog::kEvReadFail, 2, st.present, st.unknown);
                    if (prof.require_all_fields) {
                        // strict 模式：任何字段不可靠就停工，宁可停也不带错数据跑
                        running = false;
                        RLOG(Error, rlog::kEvHandleAuditDirty, 1, st.unknown, st.suspect);
                    }
                }

                // 变更检测：只记录有意义的变化
                if (hasPrev) {
                    const auto changes = state::diff(prevSnap, snap);
                    for (const auto& c : changes) {
                        if (c.becameInvalid()) {
                            RLOG(Warn, rlog::kEvReadFail, 3, 1);
                        }
                    }
                }
                prevSnap = snap;
                hasPrev = true;

                // MVP：只打印，不做决策
                if (st.present > 0) {
                    RLOG(Info, rlog::kEvSessionEnd, 3, st.present, st.total, 0);
                }
            }

            // 句柄自证
            if (!sched.assert_clean()) {
                running = false;
            }
            if (sched.stats().forced_closes > 0) {
                running = false;
            }
        }

        if (++loop > 500) running = false;  // MVP 自停
    }

    backend->shutdown();
    if (once) CloseHandle(once);
    return 0;
}
