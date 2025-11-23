@echo off
echo building stubs...
echo.

del *.obj >nul 2>&1

if "%VSCMD_ARG_TGT_ARCH%" neq "x64" (
    echo setting up x64 build environment...
    call "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64 >nul
    if %errorlevel% neq 0 (
        echo.
        echo failed to set up VS environment
        echo please run from "x64 Native Tools Command Prompt for VS 2022"
        echo.
        pause
        exit /b 1
    )
)

where cl.exe >nul 2>&1
if %errorlevel% neq 0 (
    echo cl.exe not found in PATH
    echo.
    echo please run from "x64 Native Tools Command Prompt for VS 2022"
    echo.
    pause
    exit /b 1
)

cl.exe /nologo /O2 stub_winapi.c /Fe:stub_winapi.exe /link /SUBSYSTEM:CONSOLE /MACHINE:X64 kernel32.lib user32.lib
if %errorlevel% neq 0 (
    echo.
    echo failed to build stub_winapi
    pause
    exit /b 1
)
echo built stub_winapi.exe

cl.exe /nologo /O2 stub_ntdll.c /Fe:stub_ntdll.exe /link /SUBSYSTEM:CONSOLE /MACHINE:X64 kernel32.lib user32.lib
if %errorlevel% neq 0 (
    echo.
    echo failed to build stub_ntdll
    pause
    exit /b 1
)
echo built stub_ntdll.exe

ml64.exe /nologo /c syscalls.asm
if %errorlevel% neq 0 (
    echo.
    echo failed to assemble syscalls.asm
    pause
    exit /b 1
)
echo assembled syscalls.asm

cl.exe /nologo /O2 /c stub_syscalls.c
if %errorlevel% neq 0 (
    echo.
    echo failed to compile stub_syscalls.c
    pause
    exit /b 1
)

link.exe /nologo /OUT:stub_syscalls.exe stub_syscalls.obj syscalls.obj /SUBSYSTEM:CONSOLE /MACHINE:X64 kernel32.lib user32.lib
if %errorlevel% neq 0 (
    echo.
    echo failed to link stub_syscalls
    pause
    exit /b 1
)
echo built stub_syscalls.exe

ml64.exe /nologo /c indirect.asm
if %errorlevel% neq 0 (
    echo.
    echo failed to assemble indirect.asm
    pause
    exit /b 1
)
echo assembled indirect.asm

cl.exe /nologo /O2 /c stub_indirect.c
if %errorlevel% neq 0 (
    echo.
    echo failed to compile stub_indirect.c
    pause
    exit /b 1
)

link.exe /nologo /OUT:stub_indirect.exe stub_indirect.obj indirect.obj /SUBSYSTEM:CONSOLE /MACHINE:X64 kernel32.lib user32.lib
if %errorlevel% neq 0 (
    echo.
    echo failed to link stub_indirect
    pause
    exit /b 1
)
echo built stub_indirect.exe

del *.obj >nul 2>&1
echo.
echo stub build complete
pause
