@echo off
setlocal EnableDelayedExpansion

:: Set colors for better output
for /F %%a in ('echo prompt $E ^| cmd') do set "ESC=%%a"
set "GREEN=%ESC%[32m"
set "RED=%ESC%[31m"
set "YELLOW=%ESC%[33m"
set "BLUE=%ESC%[34m"
set "NC=%ESC%[0m"

:: Check for command argument
if "%1"=="" (
    echo %YELLOW%No command specified. Use: build, run, logs, status, clean, or help%NC%
    goto :help
)

:: Set COMPOSE_CMD based on availability
where docker >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo %RED%Error: Docker is not installed or not in PATH%NC%
    echo Please install Docker Desktop from https://www.docker.com/products/docker-desktop
    pause
    exit /b 1
)
docker compose version >nul 2>&1
if %ERRORLEVEL% neq 0 (
    docker-compose --version >nul 2>&1
    if %ERRORLEVEL% neq 0 (
        echo %RED%Error: Docker Compose is not available%NC%
        echo Please ensure Docker Compose is installed
        pause
        exit /b 1
    ) else (
        set "COMPOSE_CMD=docker-compose"
        echo %YELLOW%Using legacy docker-compose command%NC%
    )
) else (
    set "COMPOSE_CMD=docker compose"
    echo %GREEN%✓ Docker Compose found%NC%
)

:: Command handling
if /i "%1"=="build" goto :build
if /i "%1"=="run" goto :run
if /i "%1"=="logs" goto :logs
if /i "%1"=="status" goto :status
if /i "%1"=="clean" goto :clean
if /i "%1"=="help" goto :help

echo %RED%Unknown command: %1%NC%
goto :help

:build
echo ================================
echo CE-CMS Container Build
echo ================================
echo %BLUE%Building containers...%NC%
echo This may take a few minutes...
%COMPOSE_CMD% build --no-cache
if %ERRORLEVEL% neq 0 (
    echo %RED%Error: Container build failed%NC%
    pause
    exit /b 1
)
echo %GREEN%✓ Container build completed%NC%
goto :end

:run
echo ================================
echo CE-CMS Security Simulation Setup
echo ================================
echo.

:: Create results directories
echo %BLUE%Creating directories...%NC%
if not exist "results" mkdir results
if not exist "results\logs" mkdir results\logs
if not exist "results\reports" mkdir results\reports
if not exist "results\metrics" mkdir results\metrics

:: Check if Docker daemon is running
docker info
if %ERRORLEVEL% neq 0 (
    echo %RED%Error: Docker daemon is not running%NC%
    echo Please start Docker Desktop
    pause
    exit /b 1
)
echo %GREEN%✓ Docker daemon is running%NC%

:: Verify config file existence
if not exist "config\network_topology.json" (
    echo %RED%Error: network_topology.json not found in config directory%NC%
    echo Please ensure the file is present and correctly placed
    pause
    exit /b 1
)
echo %GREEN%✓ Configuration file verified%NC%

echo %GREEN%Prerequisites check passed%NC%
echo.

:: Cleanup previous runs
echo %BLUE%Cleaning up previous simulation...%NC%
%COMPOSE_CMD% down --remove-orphans --volumes
if %ERRORLEVEL% neq 0 echo %YELLOW%Warning: Cleanup failed for some containers%NC%
docker system prune -f --volumes
if %ERRORLEVEL% neq 0 echo %YELLOW%Warning: System prune failed%NC%

:: Clean old logs and reports
del /Q "results\logs\*.log" 2>nul
if %ERRORLEVEL% neq 0 echo %YELLOW%Warning: Failed to delete some log files%NC%
del /Q "results\logs\*.json" 2>nul
if %ERRORLEVEL% neq 0 echo %YELLOW%Warning: Failed to delete some JSON logs%NC%
del /Q "results\reports\*.csv" 2>nul
if %ERRORLEVEL% neq 0 echo %YELLOW%Warning: Failed to delete some CSV reports%NC%
del /Q "results\reports\*.png" 2>nul
if %ERRORLEVEL% neq 0 echo %YELLOW%Warning: Failed to delete some PNG reports%NC%
del /Q "results\metrics\*.json" 2>nul
if %ERRORLEVEL% neq 0 echo %YELLOW%Warning: Failed to delete some JSON metrics%NC%
del /Q "results\metrics\*.csv" 2>nul
if %ERRORLEVEL% neq 0 echo %YELLOW%Warning: Failed to delete some CSV metrics%NC%

echo %GREEN%Cleanup completed%NC%
echo.

:: Build containers
echo %BLUE%Building containers...%NC%
echo This may take a few minutes...
%COMPOSE_CMD% build --no-cache
if %ERRORLEVEL% neq 0 (
    echo %RED%Error: Container build failed%NC%
    pause
    exit /b 1
)
echo %GREEN%✓ Container build completed%NC%
echo.

:: Start core services
echo %BLUE%Starting core services...%NC%
%COMPOSE_CMD% up -d device fog cloud metrics
if %ERRORLEVEL% neq 0 (
    echo %RED%Error: Failed to start core services%NC%
    %COMPOSE_CMD% logs > "results\logs\startup_error.log" 2>&1
    pause
    exit /b 1
)
echo %GREEN%✓ Core services started%NC%

:: Wait for services to initialize
echo %YELLOW%Waiting for services to initialize (30 seconds)...%NC%
timeout /t 30 /nobreak

:: Check service status
echo %BLUE%Checking service status...%NC%
%COMPOSE_CMD% ps > "results\logs\service_status.log" 2>&1
if %ERRORLEVEL% neq 0 echo %YELLOW%Warning: Failed to log service status%NC%

:: Verify services are healthy with retry
echo %BLUE%Verifying service health...%NC%
set "HEALTH_CHECK_FAILED=0"
set "MAX_RETRIES=3"
set "RETRY_DELAY=10"

:retry_health_checks
set "CURRENT_RETRY=0"

:check_device
powershell -Command "try { $response = Invoke-WebRequest -Uri http://device:5000/health -Method Head -UseBasicParsing; if ($response.StatusCode -eq 200) { exit 0 } else { exit 1 } } catch { exit 1 }"
if %ERRORLEVEL% neq 0 (
    set /a CURRENT_RETRY+=1
    if !CURRENT_RETRY! lss %MAX_RETRIES% (
        echo %YELLOW%Retrying device health check (!CURRENT_RETRY!/%MAX_RETRIES%)...%NC%
        timeout /t %RETRY_DELAY% /nobreak
        goto :check_device
    )
    echo %RED%✗ Device service health check failed%NC%
    set "HEALTH_CHECK_FAILED=1"
) else (
    echo %GREEN%✓ Device service is healthy%NC%
)

:check_fog
powershell -Command "try { $response = Invoke-WebRequest -Uri http://fog:6000/health -Method Head -UseBasicParsing; if ($response.StatusCode -eq 200) { exit 0 } else { exit 1 } } catch { exit 1 }"
if %ERRORLEVEL% neq 0 (
    set /a CURRENT_RETRY+=1
    if !CURRENT_RETRY! lss %MAX_RETRIES% (
        echo %YELLOW%Retrying fog health check (!CURRENT_RETRY!/%MAX_RETRIES%)...%NC%
        timeout /t %RETRY_DELAY% /nobreak
        goto :check_fog
    )
    echo %RED%✗ Fog service health check failed%NC%
    set "HEALTH_CHECK_FAILED=1"
) else (
    echo %GREEN%✓ Fog service is healthy%NC%
)

:check_cloud
powershell -Command "try { $response = Invoke-WebRequest -Uri http://cloud:7000/health -Method Head -UseBasicParsing; if ($response.StatusCode -eq 200) { exit 0 } else { exit 1 } } catch { exit 1 }"
if %ERRORLEVEL% neq 0 (
    set /a CURRENT_RETRY+=1
    if !CURRENT_RETRY! lss %MAX_RETRIES% (
        echo %YELLOW%Retrying cloud health check (!CURRENT_RETRY!/%MAX_RETRIES%)...%NC%
        timeout /t %RETRY_DELAY% /nobreak
        goto :check_cloud
    )
    echo %RED%✗ Cloud service health check failed%NC%
    set "HEALTH_CHECK_FAILED=1"
) else (
    echo %GREEN%✓ Cloud service is healthy%NC%
)

:check_metrics
powershell -Command "try { $response = Invoke-WebRequest -Uri http://metrics:8000/health -Method Head -UseBasicParsing; if ($response.StatusCode -eq 200) { exit 0 } else { exit 1 } } catch { exit 1 }"
if %ERRORLEVEL% neq 0 (
    set /a CURRENT_RETRY+=1
    if !CURRENT_RETRY! lss %MAX_RETRIES% (
        echo %YELLOW%Retrying metrics health check (!CURRENT_RETRY!/%MAX_RETRIES%)...%NC%
        timeout /t %RETRY_DELAY% /nobreak
        goto :check_metrics
    )
    echo %RED%✗ Metrics service health check failed%NC%
    set "HEALTH_CHECK_FAILED=1"
) else (
    echo %GREEN%✓ Metrics service is healthy%NC%
)

if %HEALTH_CHECK_FAILED%==1 (
    echo %YELLOW%Warning: Some services failed health checks%NC%
    echo %YELLOW%Continuing with simulation...%NC%
    echo.
)

:: Start metrics collection
echo %BLUE%Starting metrics collection...%NC%
powershell -Command "Invoke-WebRequest -Uri http://metrics:8000/start_collection -Method Post -UseBasicParsing" >nul 2>&1
if %ERRORLEVEL% neq 0 echo %YELLOW%Warning: Metrics collection start failed%NC%

:: Start log monitoring if available
powershell -Command "Invoke-WebRequest -Uri http://metrics:8001/start_monitoring -Method Post -UseBasicParsing" >nul 2>&1
if %ERRORLEVEL% neq 0 echo %YELLOW%Warning: Log monitoring start failed%NC%

echo.
echo %GREEN%Core services are running%NC%
echo %BLUE%Starting attack simulations...%NC%
echo.

:: Phase 1: Baseline measurement
echo %YELLOW%Phase 1: Baseline measurement (30 seconds)...%NC%
timeout /t 30 /nobreak

:: Phase 2: Launch attack simulations
echo %YELLOW%Phase 2: Attack simulations (90 seconds)...%NC%
%COMPOSE_CMD% --profile attacks up -d attacks
if %ERRORLEVEL% neq 0 (
    echo %RED%Error: Failed to start attack containers. Check logs.%NC%
    %COMPOSE_CMD% logs attacks > "results\logs\attacks_init_error.log" 2>&1
) else (
    echo %GREEN%✓ Attack simulations started%NC%
)

:: Monitor attack progress with detailed logging
for /L %%i in (1,1,9) do (
    echo %YELLOW%Attack simulation progress: %%i0%%%NC%
    %COMPOSE_CMD% logs attacks --tail=10 > "results\logs\attacks_progress_%%i.log" 2>&1
    timeout /t 10 /nobreak
)

:: Stop attack simulations
echo %BLUE%Stopping attack simulations...%NC%
%COMPOSE_CMD% stop attacks
if %ERRORLEVEL% neq 0 echo %YELLOW%Warning: Failed to stop attack containers%NC%
echo %GREEN%✓ Attack simulations completed%NC%

:: Phase 3: Recovery monitoring
echo %YELLOW%Phase 3: Recovery monitoring (30 seconds)...%NC%
timeout /t 30 /nobreak

:: Generate reports
echo %BLUE%Generating analysis reports...%NC%
%COMPOSE_CMD% exec -T metrics python summary_report.py
if %ERRORLEVEL% neq 0 (
    echo %RED%Warning: Report generation failed%NC%
    %COMPOSE_CMD% logs metrics > "results\logs\report_error.log" 2>&1
) else (
    echo %GREEN%✓ Reports generated%NC%
)

:: Export metrics
powershell -Command "Invoke-WebRequest -Uri http://metrics:8000/export_metrics -Method Post -UseBasicParsing" >nul 2>&1
if %ERRORLEVEL% neq 0 echo %YELLOW%Warning: Metrics export failed%NC%

echo.
echo %BLUE%Collecting container logs...%NC%

:: Collect logs from all containers with timestamp
for %%s in (device fog cloud metrics attacks) do (
    echo %BLUE%Collecting logs for %%s...%NC%
    %COMPOSE_CMD% logs %%s > "results\logs\%%s_!date!_!time:~0,2!.!time:~3,2!.log" 2>&1
    if %ERRORLEVEL% neq 0 echo %YELLOW%Warning: Failed to collect logs for %%s%NC%
)
echo %GREEN%✓ Logs collected%NC%

:: Shutdown services
echo %BLUE%Shutting down services...%NC%
%COMPOSE_CMD% down --remove-orphans
if %ERRORLEVEL% neq 0 echo %YELLOW%Warning: Shutdown failed for some containers%NC%

echo.
echo %GREEN%========================================%NC%
echo %GREEN%    CE-CMS SIMULATION COMPLETED        %NC%
echo %GREEN%========================================%NC%
echo.
echo %BLUE%Results saved to:%NC%
echo - results\logs\        (Container logs)
echo - results\reports\     (Analysis reports)  
echo - results\metrics\     (Performance data)
echo.

:: Check if reports were generated
if exist "results\reports\executive_summary.txt" (
    echo %GREEN%✓ Executive summary available%NC%
    echo.
    echo %BLUE%Executive Summary Preview:%NC%
    echo ----------------------------------------
    type "results\reports\executive_summary.txt"
    echo ----------------------------------------
    echo.
)

if exist "results\reports\ce_cms_security_analysis.png" (
    echo %GREEN%✓ Security analysis chart generated%NC%
)

if exist "results\reports\performance_metrics.csv" (
    echo %GREEN%✓ Performance metrics CSV available%NC%
)

:: Offer to open results folder
echo %YELLOW%Would you like to open the results folder? (Y/N)%NC%
set /p OPEN_RESULTS=
if /i "%OPEN_RESULTS%"=="Y" (
    start "" "results"
)

echo.
echo %BLUE%Simulation completed successfully!%NC%
echo %BLUE%Thank you for using CE-CMS Security Simulation%NC%
echo.
pause
goto :end

:logs
echo ================================
echo CE-CMS Log Monitoring
echo ================================
echo %BLUE%Monitoring logs...%NC%
%COMPOSE_CMD% logs -f
goto :end

:status
echo ================================
echo CE-CMS Status Check
echo ================================
echo %BLUE%Checking container status...%NC%
%COMPOSE_CMD% ps
goto :end

:clean
echo ================================
echo CE-CMS Cleanup
echo ================================
echo %BLUE%Cleaning up previous simulation...%NC%
%COMPOSE_CMD% down --remove-orphans --volumes
if %ERRORLEVEL% neq 0 echo %YELLOW%Warning: Cleanup failed for some containers%NC%
docker system prune -f --volumes
if %ERRORLEVEL% neq 0 echo %YELLOW%Warning: System prune failed%NC%
del /Q "results\logs\*.log" 2>nul
if %ERRORLEVEL% neq 0 echo %YELLOW%Warning: Failed to delete some log files%NC%
del /Q "results\logs\*.json" 2>nul
if %ERRORLEVEL% neq 0 echo %YELLOW%Warning: Failed to delete some JSON logs%NC%
del /Q "results\reports\*.csv" 2>nul
if %ERRORLEVEL% neq 0 echo %YELLOW%Warning: Failed to delete some CSV reports%NC%
del /Q "results\reports\*.png" 2>nul
if %ERRORLEVEL% neq 0 echo %YELLOW%Warning: Failed to delete some PNG reports%NC%
del /Q "results\metrics\*.json" 2>nul
if %ERRORLEVEL% neq 0 echo %YELLOW%Warning: Failed to delete some JSON metrics%NC%
del /Q "results\metrics\*.csv" 2>nul
if %ERRORLEVEL% neq 0 echo %YELLOW%Warning: Failed to delete some CSV metrics%NC%
echo %GREEN%✓ Cleanup completed%NC%
goto :end

:help
echo ================================
echo CE-CMS Simulation Help
echo ================================
echo Usage: run_simulation.bat [command]
echo Commands:
echo   build   - Build containers only
echo   run     - Run full simulation
echo   logs    - Show live logs
echo   status  - Show container status
echo   clean   - Clean up previous runs
echo   help    - Show this help
echo.
echo Notes:
echo - Ensure config/network_topology.json exists before running.
echo - Logs are timestamped for traceability.
goto :end

:end
exit /b 0