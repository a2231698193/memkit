# 句柄权限掩码：唯一暴露面的细节

## 为什么这件事值得单独做

句柄枚举是外部只读方案唯一的硬暴露面。但游戏看到的不只是"有个句柄"，还有**这个句柄要什么权限**。

实测两种掩码在句柄表里的样子：

```
默认为纯读取：
  请求 0x00001010  →  授予 0x00001010
  可疑度评分 0
  0x00000010  VM_READ
  0x00001000  QUERY_LIMITED

误用 kWrite（本意是纯读取）：
  授予 0x00001038
  可疑度评分 70
  危险位 2 个（VM_WRITE + VM_OPERATION）
```

差别就是这几个位。它们在 `SystemExtendedHandleInformation` 里直接可读，**一眼能看出"我想改你的内存"**。

---

## 关键：校验必须在请求之前

一旦 `NtOpenProcess` 成功，对方句柄表里就留下了你的权限请求，**无法事后补救**。

所以 `Session::Begin` 的第一件事是校验掩码，不通过就**连 OpenProcess 都不发**：

```cpp
bool Begin(DWORD pid, ACCESS_MASK mask = kReadOnly, bool allowMap = false) {
    audit_ = OpenAudit{};
    audit_.attempted = true;
    audit_.requested = mask;

    // 第一道闸：掩码检查
    const auto verdict = access::check_readonly(mask, allowMap);
    audit_.passed = verdict.ok;
    audit_.badBits = verdict.badBits;
    audit_.reason = verdict.reason;
    if (!verdict.ok) return false;    // ← 直接返回，不发起调用

    // 第二道：真正打开
    ...
}
```

---

## 掩码定义

集中在 `os/accessmask.hpp`，不允许各处自己拼：

```cpp
// 纯读取唯一允许的两位
inline constexpr ACCESS_MASK kPureRead = PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION;

// 手工映射需要的最小集合
inline constexpr ACCESS_MASK kMapNeeded = PROCESS_VM_READ | PROCESS_VM_WRITE |
                                          PROCESS_VM_OPERATION |
                                          PROCESS_QUERY_LIMITED_INFORMATION;
```

| 权限位 | 值 | 谁需要 | 纯读取要吗 |
|---|---|---|---|
| `VM_READ` | 0x10 | 读内存 | ✅ 必需 |
| `QUERY_LIMITED` | 0x1000 | 确认 pid/会话 | ✅ 常用 |
| `QUERY_FULL` | 0x400 | 查更多信息 | ❌ 比 LIMITED 显眼 |
| `VM_WRITE` | 0x20 | 写内存 | ❌ 绝不 |
| `VM_OPERATION` | 0x8 | 改页属性/分配 | ❌ 绝不 |
| `CREATE_THREAD` | 0x2 | 注入 | ❌ 绝不 |
| `DUP_HANDLE` | 0x40 | 句柄复制 | ❌ 绝不 |
| `TERMINATE` | 0x1 | 结束进程 | ❌ 绝不 |

---

## 校验规则

```cpp
Verdict check_readonly(ACCESS_MASK mask, bool allow_map = false);
```

**第一层**：只允许 `allowMap ? kMapNeeded : kPureRead` 的子集。

**第二层**（即使 `allowMap` 也执行）：永久禁止

```cpp
PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE | PROCESS_TERMINATE |
PROCESS_SUSPEND_RESUME | PROCESS_SET_INFORMATION | PROCESS_CREATE_PROCESS |
WRITE_DAC | WRITE_OWNER
```

这些是注入/破坏类，任何场景都不应该出现在一个"读内存工具"里。

---

## 实测：系统会自动加位

```
请求 0x00000038 (VM_READ|VM_WRITE|VM_OPERATION)
授予 0x00001038 (+SYNCHRONIZE 部分)
```

所以**不能简单比较"请求 == 授予"**。判定只看请求掩码本身，不问授予结果。

这一点如果搞错，会误判"权限被系统改了"，或者反过来漏掉真正的越权。

---

## 可疑度评分

用于运行时自检断言，也可用于日志诊断：

```cpp
int suspicion_score(ACCESS_MASK mask);
```

| 位 | 加权 |
|---|---|
| `CREATE_THREAD` | +100 |
| `DUP_HANDLE` | +50 |
| `VM_WRITE` | +40 |
| `VM_OPERATION` | +30 |
| `TERMINATE` | +30 |
| `SUSPEND_RESUME` | +20 |
| `SET_INFORMATION` | +20 |
| `QUERY_FULL` | +5 |
| 恰好等于 `ALL_ACCESS` | +200 |

实测：

```
kPureRead            → 0
kMapNeeded           → 70
ALL_ACCESS           → 270+
VM_READ|CREATE_THREAD→ 100+
```

---

## 审计记录

每次 `Begin` 都留下痕迹（只在内存，不落盘）：

```cpp
struct OpenAudit {
    bool attempted = false;
    bool passed = false;       // 掩码检查是否通过
    ACCESS_MASK requested = 0;
    ACCESS_MASK badBits = 0;   // 越权的位
    const char* reason = "";   // "仅读权限" / "请求了纯读取不需要的权限"
};

const OpenAudit& last_audit() const;
```

被拒的时候可以立刻知道**为什么**被拒、**哪一位**越权。这对排查"为什么映射失败"很有用——`selftest` 里就踩过：手工映射测试需要写权限，但默认 `allowMap=false` 被拦了，显式传 `true` 才通过。

---

## 测试覆盖（41 项断言）

`test_accessmask`（26 项）：

```
纯读取只含 VM_READ + QUERY_LIMITED     ✓
仅 VM_READ 通过                        ✓
仅 QUERY_LIMITED 通过                  ✓
含 VM_WRITE 被拒绝，报告越权位         ✓
含 VM_OPERATION 被拒绝                 ✓
含 CREATE_THREAD 被拒绝（即使 allowMap）✓
ALL_ACCESS 两种模式都拒绝              ✓
kMapNeeded 在 allowMap 下通过          ✓
kMapNeeded 在纯读取下被拒              ✓
最小掩码生成正确                       ✓
可疑度评分：纯读 0 / 映射 >0 / ALL >200 ✓
危险位计数正确                         ✓
位名正确                               ✓
```

`test_session_guard`（15 项）：

```
默认纯读取可打开                       ✓
带 VM_WRITE 未声明用途被拒             ✓
被拒后无句柄（未发起 OpenProcess）      ✓
CREATE_THREAD 即使 allowMap 也被拒     ✓
ALL_ACCESS 被拒                        ✓
allowMap 下映射掩码通过                ✓
审计记录 requested / passed / badBits  ✓
```

---

## 一个设计取舍

**为什么 `allowMap` 是显式参数，而不是自动推断？**

因为权限申请是**不可撤销的外部副作用**。如果自动推断（比如"检测到调用方是 manualmap 就给写权限"），一旦推断错误，句柄已经开出去了。

显式参数强制调用方声明意图：

```cpp
s.Begin(pid);                              // 纯读取，最安全
s.Begin(pid, access::kMapNeeded, true);    // 明确说要映射
```

写 `true` 这个动作本身就是一次自问："我真的需要写权限吗？"

---

## 已知限制

| 限制 | 说明 |
|---|---|
| 只校验进程句柄 | 线程句柄、文件句柄的权限未覆盖（当前用不到） |
| 不校验内核行为 | 掩码合法不代表行为合法——如果拿着 `VM_READ` 去扫全内存，对方能从读取频率看出来 |
| 系统可能加位 | `SYNCHRONIZE` 等会被自动附加，判定不能依赖相等比较 |

第二条是真正的边界：**权限掩码只证明"我申请得克制"，不证明"我用得克制"**。后者要靠 `os/guardprobe.hpp` 的读取预算来约束。
