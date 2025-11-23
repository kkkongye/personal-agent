# 一键启动两个 Octopus 实例（Windows PowerShell）
# 用法：在仓库根目录右键“使用 PowerShell 运行”或手动执行
# 需要安装 uv；若无，可改为 python -m venv + pip

$ErrorActionPreference = "Stop"

# 确定仓库根目录（脚本在 scripts/ 下，因此取其父级）
if ($PSScriptRoot) {
    $scriptDir = $PSScriptRoot
} else {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
}
$repoRoot = Split-Path -Parent $scriptDir
Set-Location $repoRoot

# 确保日志目录存在
$logs = Join-Path $repoRoot "logs"
if (-not (Test-Path $logs)) { New-Item -ItemType Directory -Path $logs | Out-Null }

# 参数可在此修改
$instanceA = @{ Port = 9527; Log = (Join-Path $logs "octopus-A.log"); Config = ".env" }
$instanceB = @{ Port = 9529; Log = (Join-Path $logs "octopus-B.log"); Config = ".env.instance_b" }

function Start-OctopusInstance {
    param(
        [int]$Port,
        [string]$Log,
        [string]$Config
    )

    $env:OCTOPUS_LOG_FILE = $Log

    $args = @("run", "python", "-m", "octopus.octopus", "--port", "$Port")
    if (Test-Path $Config) {
        $args += @("--config", $Config)
    }

    Write-Host "Starting Octopus on port $Port, log -> $Log" -ForegroundColor Green
    Start-Process -FilePath "uv" -ArgumentList $args -WorkingDirectory $repoRoot -WindowStyle Minimized
}

Start-OctopusInstance -Port $instanceA.Port -Log $instanceA.Log -Config $instanceA.Config
Start-OctopusInstance -Port $instanceB.Port -Log $instanceB.Log -Config $instanceB.Config

Write-Host "All instances launched. Press Enter to exit this launcher." -ForegroundColor Yellow
[void][System.Console]::ReadLine()
