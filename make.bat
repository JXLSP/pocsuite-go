@echo off
REM Pocsuite-Go Build Script for Windows
REM This script provides cross-platform build support for Windows, Linux, and macOS

setlocal enabledelayedexpansion

REM Configuration
set BINARY_NAME=pocsuite-go
set BUILD_DIR=bin
set VERSION=dev
set BUILD_TIME=%date:~0,4%-%date:~5,2%-%date:~8,2%T%time:~0,2%:%time:~3,2%:%time:~6,2%Z
set GIT_COMMIT=unknown

REM Try to get version from git
for /f "tokens=*" %%i in ('git describe --tags --always --dirty 2^>nul') do set VERSION=%%i
for /f "tokens=*" %%i in ('git rev-parse --short HEAD 2^>nul') do set GIT_COMMIT=%%i

REM Parse command line arguments
if "%1"=="" goto help
if "%1"=="help" goto help
if "%1"=="build" goto build
if "%1"=="build-all" goto build_all
if "%1"=="build-windows" goto build_windows
if "%1"=="build-linux" goto build_linux
if "%1"=="build-macos" goto build_macos
if "%1"=="build-windows-amd64" goto build_windows_amd64
if "%1"=="build-windows-arm64" goto build_windows_arm64
if "%1"=="build-linux-amd64" goto build_linux_amd64
if "%1"=="build-linux-arm64" goto build_linux_arm64
if "%1"=="build-macos-amd64" goto build_macos_amd64
if "%1"=="build-macos-arm64" goto build_macos_arm64
if "%1"=="clean" goto clean
if "%1"=="test" goto test
if "%1"=="run" goto run
if "%1"=="deps" goto deps
if "%1"=="fmt" goto fmt
if "%1"=="lint" goto lint
if "%1"=="release" goto release

echo Unknown target: %1
goto help

:build
echo Building %BINARY_NAME% for current platform...
if not exist %BUILD_DIR% mkdir %BUILD_DIR%
go build -ldflags "-X main.Version=%VERSION% -X main.BuildTime=%BUILD_TIME% -X main.GitCommit=%GIT_COMMIT%" -o %BUILD_DIR%\%BINARY_NAME%.exe main.go
echo Build complete: %BUILD_DIR%\%BINARY_NAME%.exe
goto end

:build_all
echo Building %BINARY_NAME% for all platforms...
call :build_windows_amd64
call :build_windows_arm64
call :build_linux_amd64
call :build_linux_arm64
call :build_macos_amd64
call :build_macos_arm64
echo All builds complete!
goto end

:build_windows
echo Building %BINARY_NAME% for all Windows platforms...
call :build_windows_amd64
call :build_windows_arm64
goto end

:build_windows_amd64
echo Building %BINARY_NAME% for Windows amd64...
if not exist %BUILD_DIR%\windows-amd64 mkdir %BUILD_DIR%\windows-amd64
set GOOS=windows
set GOARCH=amd64
go build -ldflags "-X main.Version=%VERSION% -X main.BuildTime=%BUILD_TIME% -X main.GitCommit=%GIT_COMMIT%" -o %BUILD_DIR%\windows-amd64\%BINARY_NAME%.exe main.go
echo Build complete: %BUILD_DIR%\windows-amd64\%BINARY_NAME%.exe
goto end

:build_windows_arm64
echo Building %BINARY_NAME% for Windows arm64...
if not exist %BUILD_DIR%\windows-arm64 mkdir %BUILD_DIR%\windows-arm64
set GOOS=windows
set GOARCH=arm64
go build -ldflags "-X main.Version=%VERSION% -X main.BuildTime=%BUILD_TIME% -X main.GitCommit=%GIT_COMMIT%" -o %BUILD_DIR%\windows-arm64\%BINARY_NAME%.exe main.go
echo Build complete: %BUILD_DIR%\windows-arm64\%BINARY_NAME%.exe
goto end

:build_linux
echo Building %BINARY_NAME% for all Linux platforms...
call :build_linux_amd64
call :build_linux_arm64
goto end

:build_linux_amd64
echo Building %BINARY_NAME% for Linux amd64...
if not exist %BUILD_DIR%\linux-amd64 mkdir %BUILD_DIR%\linux-amd64
set GOOS=linux
set GOARCH=amd64
go build -ldflags "-X main.Version=%VERSION% -X main.BuildTime=%BUILD_TIME% -X main.GitCommit=%GIT_COMMIT%" -o %BUILD_DIR%\linux-amd64\%BINARY_NAME% main.go
echo Build complete: %BUILD_DIR%\linux-amd64\%BINARY_NAME%
goto end

:build_linux_arm64
echo Building %BINARY_NAME% for Linux arm64...
if not exist %BUILD_DIR%\linux-arm64 mkdir %BUILD_DIR%\linux-arm64
set GOOS=linux
set GOARCH=arm64
go build -ldflags "-X main.Version=%VERSION% -X main.BuildTime=%BUILD_TIME% -X main.GitCommit=%GIT_COMMIT%" -o %BUILD_DIR%\linux-arm64\%BINARY_NAME% main.go
echo Build complete: %BUILD_DIR%\linux-arm64\%BINARY_NAME%
goto end

:build_macos
echo Building %BINARY_NAME% for all macOS platforms...
call :build_macos_amd64
call :build_macos_arm64
goto end

:build_macos_amd64
echo Building %BINARY_NAME% for macOS amd64...
if not exist %BUILD_DIR%\darwin-amd64 mkdir %BUILD_DIR%\darwin-amd64
set GOOS=darwin
set GOARCH=amd64
go build -ldflags "-X main.Version=%VERSION% -X main.BuildTime=%BUILD_TIME% -X main.GitCommit=%GIT_COMMIT%" -o %BUILD_DIR%\darwin-amd64\%BINARY_NAME% main.go
echo Build complete: %BUILD_DIR%\darwin-amd64\%BINARY_NAME%
goto end

:build_macos_arm64
echo Building %BINARY_NAME% for macOS arm64 (Apple Silicon)...
if not exist %BUILD_DIR%\darwin-arm64 mkdir %BUILD_DIR%\darwin-arm64
set GOOS=darwin
set GOARCH=arm64
go build -ldflags "-X main.Version=%VERSION% -X main.BuildTime=%BUILD_TIME% -X main.GitCommit=%GIT_COMMIT%" -o %BUILD_DIR%\darwin-arm64\%BINARY_NAME% main.go
echo Build complete: %BUILD_DIR%\darwin-arm64\%BINARY_NAME%
goto end

:clean
echo Cleaning build artifacts...
if exist %BUILD_DIR% rmdir /s /q %BUILD_DIR%
echo Clean complete!
goto end

:test
echo Running tests...
go test -v ./...
goto end

:run
echo Running %BINARY_NAME%...
go run main.go
goto end

:deps
echo Installing dependencies...
go mod download
go mod tidy
echo Dependencies installed!
goto end

:fmt
echo Formatting code...
go fmt ./...
echo Code formatted!
goto end

:lint
echo Running linter...
golangci-lint run
goto end

:release
echo Creating release packages...
call :build_all
cd %BUILD_DIR%
if exist windows-amd64 (
    powershell -Command "Compress-Archive -Path windows-amd64 -DestinationPath %BINARY_NAME%-windows-amd64-%VERSION%.zip -Force"
)
if exist windows-arm64 (
    powershell -Command "Compress-Archive -Path windows-arm64 -DestinationPath %BINARY_NAME%-windows-arm64-%VERSION%.zip -Force"
)
if exist linux-amd64 (
    tar -czf %BINARY_NAME%-linux-amd64-%VERSION%.tar.gz linux-amd64
)
if exist linux-arm64 (
    tar -czf %BINARY_NAME%-linux-arm64-%VERSION%.tar.gz linux-arm64
)
if exist darwin-amd64 (
    tar -czf %BINARY_NAME%-darwin-amd64-%VERSION%.tar.gz darwin-amd64
)
if exist darwin-arm64 (
    tar -czf %BINARY_NAME%-darwin-arm64-%VERSION%.tar.gz darwin-arm64
)
cd ..
echo Release packages created in %BUILD_DIR%/
goto end

:help
echo Pocsuite-Go Build Script for Windows
echo.
echo Usage: make.bat [target]
echo.
echo Build targets:
echo   build                  - Build for current platform
echo   build-all              - Build for all platforms (Windows/Linux/macOS)
echo   build-windows          - Build for all Windows platforms
echo   build-linux            - Build for all Linux platforms
echo   build-macos            - Build for all macOS platforms
echo   build-windows-amd64    - Build for Windows amd64
echo   build-windows-arm64    - Build for Windows arm64
echo   build-linux-amd64      - Build for Linux amd64
echo   build-linux-arm64      - Build for Linux arm64
echo   build-macos-amd64      - Build for macOS amd64
echo   build-macos-arm64      - Build for macOS arm64 (Apple Silicon)
echo.
echo Other targets:
echo   clean                  - Clean build artifacts
echo   test                   - Run tests
echo   run                    - Run the application
echo   deps                   - Install dependencies
echo   fmt                    - Format code
echo   lint                   - Run linter
echo   release                - Create release packages
echo   help                   - Show this help message
echo.
echo Examples:
echo   make.bat build-all              # Build for all platforms
echo   make.bat build-windows-amd64    # Build for Windows 64-bit
echo   make.bat build-macos-arm64      # Build for Apple Silicon
echo   make.bat release                # Create release packages
echo.

:end
endlocal
