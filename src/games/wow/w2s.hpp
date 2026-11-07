// wow/w2s.hpp —— 世界坐标 → 屏幕坐标（投影）
//
// 这是纯内存方案里唯一需要"数学"的部分。所有 ESP / 距离判断 / 目标筛选都依赖它。
//
// 关键前提：矩阵的存储顺序
// --------------------------
// 从内存读出的 16 个 float 有两种可能布局：
//
//   row-major（行主序）:      m[0] m[1] m[2] m[3]   是第一行
//   column-major（列主序）:   m[0] m[4] m[8] m[12] 是第一列
//
// OpenGL 传统用列主序，D3D 传统用行主序，但**内存里都是一样的 16 个 float**。
// 唯一可靠的办法是实测：拿两个已知世界坐标点，投影出来的屏幕位置对不对。
//
// 所以这里两种都提供，由调用方选择。默认给 row-major 版本。
//
// 数学推导（row-major，矩阵 M 作用于列向量 v）：
//
//   clip = M * (x, y, z, 1)
//   clip.x = x*M[0][0] + y*M[1][0] + z*M[2][0] + M[3][0]
//   clip.y = x*M[0][1] + y*M[1][1] + z*M[2][1] + M[3][1]
//   clip.w = x*M[0][3] + y*M[1][3] + z*M[2][3] + M[3][3]
//
//   屏幕 = ( (clip.x/clip.w + 1) * 0.5 * width,
//            (1 - clip.y/clip.w) * 0.5 * height )
//
// 注意 y 是翻转的：NDC 里 +y 向上，屏幕坐标 +y 向下。
#pragma once

#include <cmath>
#include <cstdint>

namespace wow {

struct Vec3 {
    float x = 0, y = 0, z = 0;

    Vec3 operator-(const Vec3& o) const { return {x - o.x, y - o.y, z - o.z}; }
    Vec3 operator+(const Vec3& o) const { return {x + o.x, y + o.y, z + o.z}; }

    float dot(const Vec3& o) const { return x * o.x + y * o.y + z * o.z; }

    float len() const { return std::sqrt(dot(*this)); }

    // 水平距离（忽略高度）。选目标/算贴脸距离几乎都用这个。
    float dist2d(const Vec3& o) const {
        const float dx = x - o.x, dy = y - o.y;
        return std::sqrt(dx * dx + dy * dy);
    }

    float dist3d(const Vec3& o) const { return (*this - o).len(); }
};

struct Vec2 {
    float x = 0, y = 0;
};

// 4x4 矩阵，内存中 16 个连续 float
struct Mat4 {
    float m[16] = {};

    // row-major 取元素：第 r 行第 c 列
    float at(int r, int c) const { return m[r * 4 + c]; }

    bool sane() const {
        // 判据（宽进严出）：
        //   1. 不能有 NaN / Inf
        //   2. 不能全零
        //   3. 不能是天文数字（错位后经常读到 1e30 这种）
        //
        // 注意：**不能**要求"至少 N 个非零元素"。
        // 单位矩阵只有 4 个非零（对角线），但它完全合法。
        // 早期版本要求 >=8，把单位矩阵误判成无效。
        float maxAbs = 0;
        int nonzero = 0;
        for (int i = 0; i < 16; ++i) {
            if (!std::isfinite(m[i])) return false;
            const float a = std::fabs(m[i]);
            if (a > maxAbs) maxAbs = a;
            if (a > 1e-6f) ++nonzero;
        }
        return nonzero >= 4 && maxAbs < 1e6f;
    }
};

struct Screen {
    float width = 0;
    float height = 0;
    bool valid() const { return width > 1 && height > 1; }
};

// ---------- 投影 ----------
// 返回 false 表示该点在相机背面（clip.w <= 0），不应该绘制。
inline bool world_to_screen_rowmajor(const Mat4& vm, const Vec3& p, const Screen& sc,
                                     Vec2& out) {
    if (!sc.valid()) return false;

    const float cx = p.x * vm.at(0, 0) + p.y * vm.at(1, 0) + p.z * vm.at(2, 0) + vm.at(3, 0);
    const float cy = p.x * vm.at(0, 1) + p.y * vm.at(1, 1) + p.z * vm.at(2, 1) + vm.at(3, 1);
    const float cw = p.x * vm.at(0, 3) + p.y * vm.at(1, 3) + p.z * vm.at(2, 3) + vm.at(3, 3);

    if (!(cw > 0.001f)) return false;   // 背面 / 退化

    const float ndcX = cx / cw;
    const float ndcY = cy / cw;

    // 极端视场角时 ndc 可能超界，不裁剪（由调用方按屏幕矩形自己裁）
    out.x = (ndcX + 1.0f) * 0.5f * sc.width;
    out.y = (1.0f - ndcY) * 0.5f * sc.height;
    return true;
}

inline bool world_to_screen_colmajor(const Mat4& vm, const Vec3& p, const Screen& sc,
                                     Vec2& out) {
    if (!sc.valid()) return false;

    // column-major：m[c*4+r]，等价于对 row-major 布局做转置后取 at(r,c)
    const float cx = p.x * vm.m[0] + p.y * vm.m[4] + p.z * vm.m[8]  + vm.m[12];
    const float cy = p.x * vm.m[1] + p.y * vm.m[5] + p.z * vm.m[9]  + vm.m[13];
    const float cw = p.x * vm.m[3] + p.y * vm.m[7] + p.z * vm.m[11] + vm.m[15];

    if (!(cw > 0.001f)) return false;

    out.x = (cx / cw + 1.0f) * 0.5f * sc.width;
    out.y = (1.0f - cy / cw) * 0.5f * sc.height;
    return true;
}

// 判断矩阵是什么序：用一组已知点投影，看哪个序的结果落在屏幕内且分布合理。
// 需要在真实客户端上用一次，之后固定下来。
enum class Major { Row, Col, Unknown };

inline Major guess_major(const Mat4& vm, const Vec3& probePoint, const Screen& sc) {
    Vec2 row{};
    const bool rowOk = world_to_screen_rowmajor(vm, probePoint, sc, row);

    Vec2 col{};
    const bool colOk = world_to_screen_colmajor(vm, probePoint, sc, col);

    auto inside = [&](const Vec2& v) {
        return v.x >= 0 && v.x <= sc.width && v.y >= 0 && v.y <= sc.height;
    };

    const bool rowIn = rowOk && inside(row);
    const bool colIn = colOk && inside(col);

    if (rowIn && !colIn) return Major::Row;
    if (colIn && !rowIn) return Major::Col;

    // 两个都在 / 都不在 —— 无法判定，需要更多探测点
    return Major::Unknown;
}

// ---------- 朝向 ----------
// 目标相对于玩家的角度是否在视野锥内
// 玩家 facing 是弧度，0 通常表示朝 +x 或 +y，取决于具体引擎
inline bool in_fov(float playerFacing, const Vec3& playerPos, const Vec3& targetPos,
                   float halfAngleRad, float maxDist = 100.0f) {
    const Vec3 d = targetPos - playerPos;
    const float dist = d.dist2d({});
    if (dist < 0.01f || dist > maxDist) return false;

    // 目标方向角
    const float targetAngle = std::atan2(d.y, d.x);

    // 角度差归一化到 [-pi, pi]
    float diff = targetAngle - playerFacing;
    while (diff > 3.14159265f) diff -= 6.28318530f;
    while (diff < -3.14159265f) diff += 6.28318530f;

    return std::fabs(diff) <= halfAngleRad;
}

}  // namespace wow