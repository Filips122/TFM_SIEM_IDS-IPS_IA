param(
    [string[]]$Modes = @("date", "groupkfold"),
    [string]$Dataset = "CSR-LANL",
    [string]$DatasetsBase = "src/models/CSR-LANL/datasets_redteam",

    [ValidateSet("auth", "auth_flow", "auth_flow_dns", "all")]
    [string]$SourceSet = "auth_flow",

    [string]$PythonExe = "python",
    [int]$WindowSeconds = 60,
    [double]$RedteamWindowHours = 1.0,
    [int]$RedteamWindowLimit = 0,
    [int]$RedteamExclusionWindows = 2,
    [int]$MinRedteamMatches = 1,
    [int]$ChunkSize = 250000,
    [int]$MaxRowsPerSource = 0,
    [int]$NFolds = 5,
    [int[]]$GroupFolds = @(0),
    [int]$BinaryEpochs = 215,
    [int]$MulticlassEpochs = 215,
    [int]$AnomalyEstimators = 315,
    [switch]$AllGroupFolds,
    [switch]$SkipPrepare,
    [switch]$SkipValidation,
    [switch]$SkipBinaryHgb,
    [switch]$SkipMulticlass,
    [switch]$SkipAnomaly,
    [switch]$SkipCompare,
    [switch]$NoProgress,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptDir "..\..")
$venvPython = Join-Path $repoRoot ".venv\Scripts\python.exe"
if ($PythonExe -eq "python" -and (Test-Path $venvPython)) {
    $PythonExe = $venvPython
}

$powerShellExe = $null
try {
    $powerShellExe = (Get-Process -Id $PID).Path
}
catch {
    $powerShellExe = $null
}
if ([string]::IsNullOrWhiteSpace($powerShellExe) -or !(Test-Path $powerShellExe)) {
    $powerShellExe = "powershell.exe"
}

function Quote-PowerShellValue([string]$value) {
    return "'" + ($value -replace "'", "''") + "'"
}

function Build-ChildCommand([string]$scriptPath, [string[]]$scriptArgs) {
    $arrayParams = @("-Modes", "-GroupFolds")
    $parts = @("&", (Quote-PowerShellValue $scriptPath))

    for ($i = 0; $i -lt $scriptArgs.Count; $i++) {
        $arg = $scriptArgs[$i]
        if (-not $arg.StartsWith("-")) {
            $parts += (Quote-PowerShellValue $arg)
            continue
        }

        $parts += $arg
        $values = @()
        $j = $i + 1
        while ($j -lt $scriptArgs.Count -and -not $scriptArgs[$j].StartsWith("-")) {
            $values += $scriptArgs[$j]
            $j++
        }

        if ($values.Count -eq 0) {
            continue
        }

        if ($arrayParams -contains $arg -and $values.Count -gt 1) {
            $quotedValues = @($values | ForEach-Object { Quote-PowerShellValue $_ })
            $parts += "@($($quotedValues -join ', '))"
        }
        else {
            foreach ($value in $values) {
                $parts += (Quote-PowerShellValue $value)
            }
        }

        $i = $j - 1
    }
    return ($parts -join " ")
}

function RunPy([string]$relPath, [string[]]$pyArgs) {
    $fullPath = Join-Path $repoRoot $relPath
    if (!(Test-Path $fullPath)) {
        throw "No existe el script: $fullPath"
    }
    Write-Host "`n>>> python -u $relPath $($pyArgs -join ' ')" -ForegroundColor Cyan
    if ($DryRun) {
        return
    }
    & $PythonExe -u $fullPath @pyArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Fallo: $relPath (exit code $LASTEXITCODE)"
    }
}

function RunScript([string]$relPath, [string[]]$scriptArgs) {
    $fullPath = Join-Path $repoRoot $relPath
    if (!(Test-Path $fullPath)) {
        throw "No existe el script: $fullPath"
    }
    Write-Host "`n>>> $relPath $($scriptArgs -join ' ')" -ForegroundColor Cyan
    if ($DryRun) {
        return
    }

    $childCommand = Build-ChildCommand $fullPath $scriptArgs
    & $powerShellExe -NoProfile -ExecutionPolicy Bypass -Command $childCommand
    if ($LASTEXITCODE -ne 0) {
        throw "Fallo: $relPath (exit code $LASTEXITCODE)"
    }
}

Write-Host "=== CSR-LANL red-team-centered flow ===" -ForegroundColor Green
Write-Host "Repo root     : $repoRoot"
Write-Host "Python        : $PythonExe"
Write-Host "DatasetsBase  : $DatasetsBase"
Write-Host "Modes         : $($Modes -join ', ')"
Write-Host "Source set    : $SourceSet"
Write-Host "Redteam window: +/- $RedteamWindowHours hour(s); limit=$RedteamWindowLimit"

if (-not $SkipPrepare) {
    $prepareArgs = @(
        "--out_dir", $DatasetsBase,
        "--dataset", $Dataset,
        "--source_set", $SourceSet,
        "--split_mode"
    ) + $Modes + @(
        "--window_seconds", "$WindowSeconds",
        "--redteam_window_hours", "$RedteamWindowHours",
        "--redteam_window_limit", "$RedteamWindowLimit",
        "--redteam_exclusion_windows", "$RedteamExclusionWindows",
        "--min_redteam_matches", "$MinRedteamMatches",
        "--chunk_size", "$ChunkSize",
        "--n_folds", "$NFolds"
    )
    if ($AllGroupFolds) {
        $prepareArgs += "--all_folds"
    }
    else {
        $prepareArgs += @("--fold", "$($GroupFolds[0])")
    }
    if ($MaxRowsPerSource -gt 0) {
        $prepareArgs += @("--max_rows_per_source", "$MaxRowsPerSource")
    }
    if ($NoProgress) {
        $prepareArgs += "--no_progress"
    }
    RunPy "src\models\CSR-LANL\redteam_sample_prepare_dataset.py" $prepareArgs
}

if (-not $SkipValidation) {
    RunPy "src\models\CSR-LANL\validate_datasets.py" (@(
        "--datasets_base", $DatasetsBase,
        "--dataset", $Dataset,
        "--modes"
    ) + $Modes)
}

$trainArgs = @(
    "-Modes"
) + $Modes + @(
    "-Dataset", $Dataset,
    "-DatasetsBase", $DatasetsBase,
    "-PythonExe", $PythonExe,
    "-BinaryEpochs", "$BinaryEpochs",
    "-MulticlassEpochs", "$MulticlassEpochs",
    "-AnomalyEstimators", "$AnomalyEstimators",
    "-NFolds", "$NFolds",
    "-GroupFolds"
) + @($GroupFolds | ForEach-Object { "$($_)" })

if ($AllGroupFolds) { $trainArgs += "-AllGroupFolds" }
if ($SkipBinaryHgb) { $trainArgs += "-SkipBinaryHgb" }
if ($SkipMulticlass) { $trainArgs += "-SkipMulticlass" }
if ($SkipAnomaly) { $trainArgs += "-SkipAnomaly" }
if ($SkipCompare) { $trainArgs += "-SkipCompare" }
if ($DryRun) { $trainArgs += "-DryRun" }

RunScript "src\scripts\csr_lanl_run_all_models.ps1" $trainArgs

Write-Host "`nCSR-LANL red-team-centered flow finished." -ForegroundColor Green