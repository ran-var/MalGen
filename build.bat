@echo off
echo ━━━━ building MalGen ━━━━
echo.

echo building stubs...
cd src\stubs
call build_stubs.bat
if %errorlevel% neq 0 (
    echo stub build failed
    cd ..\..
    exit /b 1
)
cd ..\..
echo.

echo building main project...
msbuild Malgen.sln /p:Configuration=Release /p:Platform=x64 /v:minimal /nologo
if %errorlevel% neq 0 (
    echo main build failed
    exit /b 1
)

echo.
echo ━━━━ build complete ━━━━
echo run: x64\Release\Malgen.exe
