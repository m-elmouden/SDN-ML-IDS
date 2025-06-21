# RabbitMQ-based IDS System Startup Script for Windows
# PowerShell script to start all services in the correct order

param(
    [string]$ComposeFile = "docker-compose-rabbitmq.yml",
    [string]$ProjectName = "ids-rabbitmq"
)

# Configuration
$ErrorActionPreference = "Stop"

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "INFO" { "Blue" }
        "SUCCESS" { "Green" }
        "WARNING" { "Yellow" }
        "ERROR" { "Red" }
        default { "White" }
    }
    
    Write-Host "[$Level] $timestamp - $Message" -ForegroundColor $color
}

function Test-ServiceHealth {
    param(
        [string]$ServiceName,
        [int]$MaxAttempts = 10
    )
    
    Write-Log "Checking health of service: $ServiceName"
    
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            $status = docker-compose -f $ComposeFile -p $ProjectName ps $ServiceName
            if ($status -match "healthy|Up") {
                Write-Log "$ServiceName is healthy" "SUCCESS"
                return $true
            }
        }
        catch {
            Write-Log "Error checking service status: $_" "WARNING"
        }
        
        Write-Log "Attempt $attempt/$MaxAttempts`: $ServiceName not ready yet, waiting..." "INFO"
        Start-Sleep -Seconds 5
    }
    
    Write-Log "$ServiceName failed to become healthy after $MaxAttempts attempts" "ERROR"
    return $false
}

function Setup-RabbitMQ {
    Write-Log "Setting up RabbitMQ..." "INFO"
    
    # Wait for RabbitMQ to be ready
    if (Test-ServiceHealth -ServiceName "rabbitmq" -MaxAttempts 12) {
        Write-Log "RabbitMQ is ready" "SUCCESS"
        
        # Wait a bit more for management API to be fully ready
        Start-Sleep -Seconds 10
        
        Write-Log "Creating RabbitMQ queues..." "INFO"
        
        # Create features queue
        try {
            docker-compose -f $ComposeFile -p $ProjectName exec rabbitmq rabbitmqadmin declare queue name=features durable=true
            Write-Log "Features queue created" "SUCCESS"
        }
        catch {
            Write-Log "Failed to create features queue (may already exist)" "WARNING"
        }
        
        # Create decisions queue
        try {
            docker-compose -f $ComposeFile -p $ProjectName exec rabbitmq rabbitmqadmin declare queue name=decisions durable=true
            Write-Log "Decisions queue created" "SUCCESS"
        }
        catch {
            Write-Log "Failed to create decisions queue (may already exist)" "WARNING"
        }
        
        Write-Log "RabbitMQ setup completed" "SUCCESS"
        return $true
    }
    else {
        Write-Log "RabbitMQ failed to start properly" "ERROR"
        return $false
    }
}

function Show-ServiceStatus {
    Write-Log "Service Status:" "INFO"
    Write-Host "=" * 50 -ForegroundColor Cyan
    docker-compose -f $ComposeFile -p $ProjectName ps
    Write-Host "=" * 50 -ForegroundColor Cyan
    Write-Host ""
}

function Show-AccessUrls {
    Write-Host ""
    Write-Log "System is ready! Access points:" "SUCCESS"
    Write-Host "=" * 50 -ForegroundColor Green
    Write-Host "🐰 RabbitMQ Management UI: http://localhost:15672" -ForegroundColor Green
    Write-Host "   Username: guest, Password: guest" -ForegroundColor Gray
    Write-Host ""
    Write-Host "📊 Dashboard: http://localhost:8080" -ForegroundColor Green
    Write-Host ""
    Write-Host "🤖 ML Model API: http://localhost:5000" -ForegroundColor Green
    Write-Host "   Health: http://localhost:5000/health" -ForegroundColor Gray
    Write-Host "   Predict: http://localhost:5000/predict" -ForegroundColor Gray
    Write-Host ""
    Write-Host "🐳 Portainer: http://localhost:9000" -ForegroundColor Green
    Write-Host "=" * 50 -ForegroundColor Green
    Write-Host ""
}

function Cleanup-PreviousRuns {
    Write-Log "Cleaning up previous runs..." "INFO"
    try {
        docker-compose -f $ComposeFile -p $ProjectName down -v 2>$null
        docker system prune -f 2>$null
        Write-Log "Cleanup completed" "SUCCESS"
    }
    catch {
        Write-Log "Cleanup encountered some issues, but continuing..." "WARNING"
    }
}

function Stop-Services {
    Write-Host ""
    Write-Log "Stopping services gracefully..." "INFO"
    try {
        docker-compose -f $ComposeFile -p $ProjectName down
        Write-Log "All services stopped" "SUCCESS"
    }
    catch {
        Write-Log "Error stopping services: $_" "ERROR"
    }
}

# Main execution
try {
    Write-Host "=" * 50 -ForegroundColor Cyan
    Write-Host "Starting RabbitMQ-based IDS System" -ForegroundColor Cyan
    Write-Host "=" * 50 -ForegroundColor Cyan
    
    # Check if Docker and Docker Compose are available
    try {
        docker --version | Out-Null
        docker-compose --version | Out-Null
    }
    catch {
        Write-Log "Docker or Docker Compose is not installed or not in PATH" "ERROR"
        exit 1
    }
    
    # Check if compose file exists
    if (-not (Test-Path $ComposeFile)) {
        Write-Log "Docker Compose file not found: $ComposeFile" "ERROR"
        exit 1
    }
    
    # Clean up any previous runs
    Cleanup-PreviousRuns
    
    # Start all services
    Write-Log "Starting all services..." "INFO"
    docker-compose -f $ComposeFile -p $ProjectName up -d
    
    # Wait for RabbitMQ and set it up
    if (-not (Setup-RabbitMQ)) {
        Write-Log "Failed to setup RabbitMQ" "ERROR"
        exit 1
    }
    
    # Wait for ML model to be ready
    Write-Log "Waiting for ML model to be ready..." "INFO"
    if (Test-ServiceHealth -ServiceName "ml-model" -MaxAttempts 20) {
        Write-Log "ML model is ready" "SUCCESS"
    }
    else {
        Write-Log "ML model may not be fully ready, but continuing..." "WARNING"
    }
    
    # Show final status
    Show-ServiceStatus
    Show-AccessUrls
    
    Write-Log "System started successfully! Press Ctrl+C to stop." "SUCCESS"
    Write-Log "Following logs from all services..." "INFO"
    Write-Host ""
    
    # Setup cleanup on Ctrl+C
    Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
        Stop-Services
    }
    
    # Follow logs from all services
    try {
        docker-compose -f $ComposeFile -p $ProjectName logs -f
    }
    catch {
        Write-Log "Logs interrupted" "INFO"
    }
    finally {
        Stop-Services
    }
}
catch {
    Write-Log "An error occurred: $_" "ERROR"
    Stop-Services
    exit 1
}
