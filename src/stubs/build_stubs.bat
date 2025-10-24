@echo off
echo building stubs...

cl.exe /nologo /O2 stub_winapi.c /Fe:stub_winapi.exe /link /SUBSYSTEM:CONSOLE kernel32.lib >nul 2>&1
if %errorlevel% neq 0 (
    echo failed to build stub_winapi
    exit /b 1
)
echo built stub_winapi.exe

cl.exe /nologo /O2 stub_ntdll.c /Fe:stub_ntdll.exe /link /SUBSYSTEM:CONSOLE kernel32.lib >nul 2>&1
if %errorlevel% neq 0 (
    echo failed to build stub_ntdll
    exit /b 1
)
echo built stub_ntdll.exe

del *.obj >nul 2>&1
echo stub build complete
