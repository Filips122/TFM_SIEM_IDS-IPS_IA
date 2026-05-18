param(
    [string[]]$Modes = @("random"),
    [string]$Dataset = "CSR-LANL",
    [string]$DatasetsBase = "src/models/CSR-LANL/datasets_subsample",
    [string]$PythonExe = "python",
    [int]$BinaryEpochs = 215,
    [int]$MulticlassEpochs = 215,
    [int]$AnomalyEstimators = 315,
    [double]$SampleFrac,
    [switch]$SkipBinaryHgb,
    [switch]$SkipMulticlass,
    [switch]$SkipAnomaly,
    [switch]$SkipCompare,
    [switch]$SkipDatasetCheck,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$allowedModes = @("date", "random", "groupkfold")
$normalizedModes = @()
foreach ($modeArg in $Modes) {
    foreach ($part in @($modeArg -split ",")) {
        $candidate = $part.Trim().ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($candidate)) {
            continue
        }
        if ($candidate -eq "all") {
            $normalizedModes += $allowedModes
            continue
        }
        if ($allowedModes -notcontains $candidate) {
            throw "Invalid mode '$candidate'. Allowed values: $($allowedModes -join ', ')"
        }
        $normalizedModes += $candidate
    }
}
$Modes = @($normalizedModes | Select-Object -Unique)
if (-not $Modes -or $Modes.Count -eq 0) {
    throw "At least one mode is required."
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptDir "..\..")
$datasetsBaseFull = Join-Path $repoRoot $DatasetsBase
$artifactsDir = Join-Path $repoRoot "src\models\CSR-LANL\artifacts"
$venvPython = Join-Path $repoRoot ".venv\Scripts\python.exe"
if ($PythonExe -eq "python" -and (Test-Path $venvPython)) {
    $PythonExe = $venvPython
}
$hasSampleFrac = $PSBoundParameters.ContainsKey("SampleFrac")

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

function Test-ParquetFolder([string]$folder) {
    if (!(Test-Path $folder)) {
        return $false
    }
    $first = Get-ChildItem -Path $folder -Filter "*.parquet" -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1
    return $null -ne $first
}

function Get-DatasetRoot([string]$mode) {
    return Join-Path $datasetsBaseFull (Join-Path $mode $Dataset)
}

function Test-PipelineReady([string]$baseDir, [string]$pipeline) {
    if ($pipeline -eq "anomaly") {
        $folders = @(
            (Join-Path $baseDir "anomaly\train_benign")
            (Join-Path $baseDir "anomaly\val_mixed")
            (Join-Path $baseDir "anomaly\test_mixed")
        )
    }
    else {
        $folders = @(
            (Join-Path $baseDir "$pipeline\train")
            (Join-Path $baseDir "$pipeline\val")
            (Join-Path $baseDir "$pipeline\test")
        )
    }

    $missing = @()
    foreach ($folder in $folders) {
        if (!(Test-ParquetFolder $folder)) {
            $missing += $folder
        }
    }

    return @{
        Ready = ($missing.Count -eq 0)
        Missing = $missing
    }
}

function Assert-PipelineReady([string]$mode, [string]$pipeline) {
    if ($SkipDatasetCheck) {
        return
    }

    if ($mode -eq "groupkfold") {
        throw "groupkfold mode is only supported after preparing groupkfold CSR-LANL splits. Use -SkipDatasetCheck only if those splits already exist."
    }

    $status = Test-PipelineReady (Get-DatasetRoot $mode) $pipeline
    if (-not $status.Ready) {
        throw "Dataset '$Dataset' is not ready for pipeline '$pipeline' in mode '$mode'. Missing parquet files in: $($status.Missing -join ', ')"
    }
}

function New-TrainerArgs([string]$mode, [int]$epochs) {
    $args = @(
        "--datasets_base", "$DatasetsBase",
        "--split_mode", $mode,
        "--dataset", $Dataset,
        "--epochs", "$epochs"
    )
    if ($hasSampleFrac) {
        $args += @("--sample_frac", "$SampleFrac")
    }
    return $args
}

Write-Host "=== CSR-LANL model training ===" -ForegroundColor Green
Write-Host "Repo root    : $repoRoot"
Write-Host "Python       : $PythonExe"
Write-Host "Dataset      : $Dataset"
Write-Host "DatasetsBase : $datasetsBaseFull"
Write-Host "Modes        : $($Modes -join ', ')"
Write-Host "Dry run      : $DryRun"

foreach ($mode in $Modes) {
    if (-not $SkipBinaryHgb) {
        Assert-PipelineReady $mode "binary"
    }
    if (-not $SkipMulticlass) {
        Assert-PipelineReady $mode "multiclass"
    }
    if (-not $SkipAnomaly) {
        Assert-PipelineReady $mode "anomaly"
    }

    if (-not $SkipBinaryHgb) {
        RunPy "src\models\CSR-LANL\train_ml_binary_hgb.py" (New-TrainerArgs $mode $BinaryEpochs)
    }
    if (-not $SkipMulticlass) {
        RunPy "src\models\CSR-LANL\train_ml_multiclass_hgb.py" (New-TrainerArgs $mode $MulticlassEpochs)
    }
    if (-not $SkipAnomaly) {
        RunPy "src\models\CSR-LANL\train_anomaly_isoforest.py" @(
            "--datasets_base", "$DatasetsBase",
            "--split_mode", $mode,
            "--dataset", $Dataset,
            "--epochs", "$AnomalyEstimators"
        )
    }
}

if (-not $SkipCompare) {
    RunPy "src\models\CSR-LANL\compare_models.py" @("--artifacts_dir", "$artifactsDir")
}

Write-Host "`nCSR-LANL model training finished." -ForegroundColor Green