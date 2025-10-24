@echo off
echo building stubs...
echo.

where cl.exe >nul 2>&1
if %errorlevel% neq 0 (
    echo cl.exe not found in PATH
    echo.
    echo please run from "x64 Native Tools Command Prompt for VS 2022"
    echo.
    pause
    exit /b 1
)

cl.exe /nologo /O2 stub_winapi.c /Fe:stub_winapi.exe /link /SUBSYSTEM:CONSOLE kernel32.lib
if %errorlevel% neq 0 (
    echo.
    echo failed to build stub_winapi
    pause
    exit /b 1
)
echo built stub_winapi.exe

cl.exe /nologo /O2 stub_ntdll.c /Fe:stub_ntdll.exe /link /SUBSYSTEM:CONSOLE kernel32.lib
if %errorlevel% neq 0 (
    echo.
    echo failed to build stub_ntdll
    pause
    exit /b 1
)
echo built stub_ntdll.exe

del *.obj >nul 2>&1
echo.
echo stub build complete
pause
