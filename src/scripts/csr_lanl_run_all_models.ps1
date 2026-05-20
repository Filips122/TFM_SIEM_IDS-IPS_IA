param(
    [string[]]$Modes = @("random"),
    [string]$Dataset = "CSR-LANL",
    [string]$DatasetsBase = "src/models/CSR-LANL/datasets_subsample",
    [string]$PythonExe = "python",
    [int]$BinaryEpochs = 215,
    [int]$MulticlassEpochs = 215,
    [int]$AnomalyEstimators = 315,
    [int]$NFolds = 5,
    [int[]]$GroupFolds = @(0),
    [double]$SampleFrac,
    [switch]$AllGroupFolds,
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

function Assert-PipelineReady([string]$mode, [string]$pipeline, [int]$fold = -1) {
    if ($SkipDatasetCheck) {
        return
    }

    $baseDir = Get-DatasetRoot $mode
    if ($mode -eq "groupkfold") {
        if ($fold -lt 0) {
            throw "groupkfold dataset check requires a fold number."
        }
        $baseDir = Join-Path $baseDir "fold_$fold"
    }

    $status = Test-PipelineReady $baseDir $pipeline
    if (-not $status.Ready) {
        $foldText = if ($mode -eq "groupkfold") { " fold_$fold" } else { "" }
        throw "Dataset '$Dataset' is not ready for pipeline '$pipeline' in mode '$mode'$foldText. Missing parquet files in: $($status.Missing -join ', ')"
    }
}

function New-TrainerArgs([string]$mode, [int]$epochs, [int]$fold = -1, [switch]$AllFolds) {
    $args = @(
        "--datasets_base", "$DatasetsBase",
        "--split_mode", $mode,
        "--dataset", $Dataset,
        "--epochs", "$epochs"
    )
    if ($mode -eq "groupkfold") {
        if ($AllFolds) {
            $args += @("--all_folds", "--n_folds", "$NFolds")
        }
        else {
            $args += @("--fold", "$fold", "--n_folds", "$NFolds")
        }
    }
    if ($hasSampleFrac) {
        $args += @("--sample_frac", "$SampleFrac")
    }
    return $args
}

function Invoke-SupervisedTrainer([string]$relPath, [string]$mode, [int]$epochs) {
    if ($mode -ne "groupkfold") {
        RunPy $relPath (New-TrainerArgs $mode $epochs)
        return
    }

    if ($AllGroupFolds) {
        RunPy $relPath (New-TrainerArgs $mode $epochs -AllFolds)
        return
    }

    foreach ($fold in $GroupFolds) {
        RunPy $relPath (New-TrainerArgs $mode $epochs $fold)
    }
}

function Invoke-AnomalyTrainer([string]$mode) {
    if ($mode -ne "groupkfold") {
        RunPy "src\models\CSR-LANL\train_anomaly_isoforest.py" @(
            "--datasets_base", "$DatasetsBase",
            "--split_mode", $mode,
            "--dataset", $Dataset,
            "--epochs", "$AnomalyEstimators"
        )
        return
    }

    if ($AllGroupFolds) {
        RunPy "src\models\CSR-LANL\train_anomaly_isoforest.py" @(
            "--datasets_base", "$DatasetsBase",
            "--split_mode", $mode,
            "--dataset", $Dataset,
            "--epochs", "$AnomalyEstimators",
            "--all_folds",
            "--n_folds", "$NFolds"
        )
        return
    }

    foreach ($fold in $GroupFolds) {
        RunPy "src\models\CSR-LANL\train_anomaly_isoforest.py" @(
            "--datasets_base", "$DatasetsBase",
            "--split_mode", $mode,
            "--dataset", $Dataset,
            "--epochs", "$AnomalyEstimators",
            "--fold", "$fold",
            "--n_folds", "$NFolds"
        )
    }
}

Write-Host "=== CSR-LANL model training ===" -ForegroundColor Green
Write-Host "Repo root    : $repoRoot"
Write-Host "Python       : $PythonExe"
Write-Host "Dataset      : $Dataset"
Write-Host "DatasetsBase : $datasetsBaseFull"
Write-Host "Modes        : $($Modes -join ', ')"
Write-Host "Group folds  : $(if ($AllGroupFolds) { 'all' } else { $GroupFolds -join ', ' })"
Write-Host "Dry run      : $DryRun"

foreach ($mode in $Modes) {
    $foldsToCheck = if ($mode -eq "groupkfold") {
        if ($AllGroupFolds) { 0..($NFolds - 1) } else { $GroupFolds }
    }
    else {
        @(-1)
    }

    if (-not $SkipBinaryHgb) {
        foreach ($fold in $foldsToCheck) { Assert-PipelineReady $mode "binary" $fold }
    }
    if (-not $SkipMulticlass) {
        foreach ($fold in $foldsToCheck) { Assert-PipelineReady $mode "multiclass" $fold }
    }
    if (-not $SkipAnomaly) {
        foreach ($fold in $foldsToCheck) { Assert-PipelineReady $mode "anomaly" $fold }
    }

    if (-not $SkipBinaryHgb) {
        Invoke-SupervisedTrainer "src\models\CSR-LANL\train_ml_binary_hgb.py" $mode $BinaryEpochs
    }
    if (-not $SkipMulticlass) {
        Invoke-SupervisedTrainer "src\models\CSR-LANL\train_ml_multiclass_hgb.py" $mode $MulticlassEpochs
    }
    if (-not $SkipAnomaly) {
        Invoke-AnomalyTrainer $mode
    }
}

if (-not $SkipCompare) {
    $compareArgs = @("--artifacts_dir", "$artifactsDir", "--split_modes") + $Modes
    RunPy "src\models\CSR-LANL\compare_models.py" $compareArgs
}

Write-Host "`nCSR-LANL model training finished." -ForegroundColor Green