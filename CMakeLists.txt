cmake_minimum_required(VERSION 3.20)
project(memkit LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

# 游戏层：默认关闭，各 game/* 分支在 configure 时打开
option(MEMKIT_GAME_WOW "Build World of Warcraft support layer" OFF)

add_executable(memkit
    src/app/main.cpp
    src/app/wrap_stub.cpp
)

# 离线自检入口：不进正式二进制，供开发期验证行为
option(MEMKIT_SELFTEST "Build offline selftest binary" OFF)
if(MEMKIT_SELFTEST)
    add_executable(selftest
        src/app/selftest.cpp
        src/app/wrap_stub.cpp
    )
    target_include_directories(selftest PRIVATE src)
    target_compile_definitions(selftest PRIVATE
        WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS _WIN32_WINNT=0x0A00)
    if(MEMKIT_GAME_WOW)
        target_compile_definitions(selftest PRIVATE MEMKIT_GAME_WOW=1)
    endif()
    target_link_libraries(selftest PRIVATE bcrypt)
    if(NOT MSVC)
        target_compile_options(selftest PRIVATE -O2 -fno-rtti -fno-exceptions -Wall -Wextra -Wno-unused-parameter)
        target_link_options(selftest PRIVATE -static
            -Wl,--wrap=__imp_OpenProcess -Wl,--wrap=__imp_DuplicateHandle
            -Wl,--wrap=__imp_SuspendThread -Wl,--wrap=__imp_ResumeThread
            -Wl,--wrap=__imp_SetThreadContext -Wl,--wrap=__imp_GetThreadContext)
    endif()
endif()

target_include_directories(memkit PRIVATE src)
target_compile_definitions(memkit PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    _CRT_SECURE_NO_WARNINGS
    _WIN32_WINNT=0x0A00
)

# ---------------- 二进制卫生 / 隐蔽性编译约束 ----------------
if(MSVC)
    target_compile_options(memkit PRIVATE
        /MT            # 静态 CRT，不留 vcruntime140.dll 依赖
        /O2 /Oi /Gy
        /GR-           # 关 RTTI，减少 type_info 字符串
        /GS-           # 关栈 cookie（不引入 __security_cookie 特征）
        /guard:cf-     # 关 CFG 元数据
        /permissive-
        /W4
        /utf-8
        /Zc:inline
    )
    target_compile_options(memkit PRIVATE $<$<CONFIG:Release>:/DNDEBUG>)
    target_link_options(memkit PRIVATE
        /DEBUG:NONE
        /OPT:REF /OPT:ICF
        /INCREMENTAL:NO
        /MANIFEST:NO
    )
    # MSVC 侧同样做符号重定向（若运行库间接引用，同样被拦）
    set_target_properties(memkit PROPERTIES
        LINK_FLAGS "/PDBALTPATH:%_PDB% /ALTERNATENAME:OpenProcess=wrap_open_process \
                     /ALTERNATENAME:DuplicateHandle=wrap_duplicate_handle"   # 只留文件名，不泄漏构建路径
    )
else()
    # MinGW-w64 路径（本机验证用）
    target_compile_options(memkit PRIVATE
        -O2 -ffunction-sections -fdata-sections
        -fno-rtti
        -fno-exceptions
        -fno-threadsafe-statics
        -fno-ident
        -Wall -Wextra -Wno-unused-parameter
    )
    target_link_options(memkit PRIVATE
        -static                 # 静态 libgcc/libstdc++/winpthread
        -municode
        -s                      # 剥符号
        -Wl,--gc-sections
        -Wl,--no-insert-timestamp
        -Wl,--build-id=none
        -Wl,--dynamicbase
        -Wl,--nxcompat
        # 拦截运行库对敏感 API 的间接引用，避免导入表污染
        -Wl,--wrap=__imp_OpenProcess
        -Wl,--wrap=__imp_DuplicateHandle
        -Wl,--wrap=__imp_SuspendThread
        -Wl,--wrap=__imp_ResumeThread
        -Wl,--wrap=__imp_SetThreadContext
        -Wl,--wrap=__imp_GetThreadContext
    )
endif()

# 系统库：bcrypt 用于 BCryptGenRandom；其余经哈希解析不直接链接
target_link_libraries(memkit PRIVATE bcrypt)

# ---------------- 构建后卫生处理 ----------------
find_program(OBJCOPY_EXE NAMES objcopy x86_64-w64-mingw32-objcopy)
if(OBJCOPY_EXE AND NOT MSVC)
    add_custom_command(TARGET memkit POST_BUILD
        COMMAND ${OBJCOPY_EXE} --strip-all --remove-section=.comment
                --remove-section=.note.gnu.property
                $<TARGET_FILE:memkit>
        COMMENT "stripping sections / comment / note"
    )
endif()

# ---------------- 内核驱动（可选，需要 WDK）----------------
#
# WDK 的 km 头与 MinGW 的 winnt.h 冲突（同一套结构体定义两遍），
# 没法塞进同一个 CMake target。这里用独立的外部构建脚本，
# CMake 只负责在检测到 WDK + MSVC 时调用它。
option(MEMKIT_BUILD_DRIVER "Build kernel driver (requires WDK + MSVC)" OFF)
if(MEMKIT_BUILD_DRIVER)
    find_program(VSWHERE_EXE NAMES vswhere
        PATHS "C:/Program Files (x86)/Microsoft Visual Studio/Installer")
    set(WDK_ROOT "C:/Program Files (x86)/Windows Kits/10" CACHE PATH "WDK root")
    set(WDK_VER "10.0.26100.0" CACHE STRING "WDK version")

    if(VSWHERE_EXE AND EXISTS "${WDK_ROOT}/Include/${WDK_VER}/km/ntddk.h")
        add_custom_target(driver ALL
            COMMAND ${CMAKE_COMMAND} -E echo "Building kernel driver (WDK ${WDK_VER})"
            COMMAND cmd /c "${CMAKE_CURRENT_SOURCE_DIR}/driver/build.bat"
            WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/driver"
            COMMENT "memkit_drv.sys"
            VERBATIM)
    else()
        message(STATUS "WDK ${WDK_VER} or MSVC not found, skipping driver")
    endif()
endif()

# ---------------- 实测工具（决定架构的探针程序）----------------
# 这些小工具不进正式二进制，只在开发期用来回答"某个通道在某一层是否可见"。
option(MEMKIT_BUILD_PROBES "Build diagnostic probes (rawspy/llspy/hookdetect)" OFF)
if(MEMKIT_BUILD_PROBES AND NOT MSVC)
    foreach(p rawspy llspy hookdetect)
        add_executable(probe_${p} tools/${p}.cpp)
        target_compile_definitions(probe_${p} PRIVATE
            WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS _WIN32_WINNT=0x0A00)
        target_compile_options(probe_${p} PRIVATE -O2 -static -Wall)
        target_link_options(probe_${p} PRIVATE -static)
        target_link_libraries(probe_${p} PRIVATE user32)
    endforeach()
endif()
