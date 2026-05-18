param(
    [string[]]$Modes = @("date"),
    [string]$Dataset = "COWRIE_FULL",
    [string]$PythonExe = "python",
    [string]$WindowSize = "1min",
    [int]$Seed = 42,
    [int]$NFolds = 5,
    [int[]]$GroupFolds = @(0),
    [int]$BinaryEpochs = 215,
    [int]$MulticlassEpochs = 215,
    [int]$AnomalyEstimators = 315,
    [int]$MinMulticlassWindows = 30,
    [int]$FailedLoginThreshold = 3,
    [int]$AnomalyNJobs = 1,
    [double]$SampleFrac,
    [switch]$AllGroupFolds,
    [switch]$SkipPreprocess,
    [switch]$SkipBinaryHgb,
    [switch]$SkipMulticlass,
    [switch]$SkipAnomaly,
    [switch]$SkipCompare,
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
$Modes = $normalizedModes | Select-Object -Unique
if (-not $Modes -or $Modes.Count -eq 0) {
    throw "At least one mode is required."
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptDir "..\..")
$venvPython = Join-Path $repoRoot ".venv\Scripts\python.exe"
if ($PythonExe -eq "python" -and (Test-Path $venvPython)) {
    $PythonExe = $venvPython
}
$hasSampleFrac = $PSBoundParameters.ContainsKey("SampleFrac")

function RunPy {
    param(
        [string]$relPath,
        [string[]]$pythonParams
    )

    $fullPath = Join-Path $repoRoot $relPath
    if (!(Test-Path $fullPath)) {
        throw "No existe el script: $fullPath"
    }
    Write-Host "`n>>> python -u $relPath $($pythonParams -join ' ')" -ForegroundColor Cyan
    if ($DryRun) {
        return
    }
    & $PythonExe -u $fullPath @pythonParams
    if ($LASTEXITCODE -ne 0) {
        throw "Fallo: $relPath (exit code $LASTEXITCODE)"
    }
}

function New-TrainerParams {
    param(
        [string]$mode,
        [int]$epochs
    )

    if ($hasSampleFrac) {
        return @("--split_mode", $mode, "--dataset", $Dataset, "--epochs", "$epochs", "--sample_frac", "$SampleFrac")
    }
    return @("--split_mode", $mode, "--dataset", $Dataset, "--epochs", "$epochs")
}

function Invoke-GroupedTrainer {
    param(
        [string]$relPath,
        [int]$epochs,
        [switch]$NoSampleFrac
    )

    if ($AllGroupFolds) {
        if ($hasSampleFrac -and -not $NoSampleFrac) {
            RunPy $relPath @("--split_mode", "groupkfold", "--dataset", $Dataset, "--all_folds", "--n_folds", "$NFolds", "--epochs", "$epochs", "--sample_frac", "$SampleFrac")
            return
        }
        RunPy $relPath @("--split_mode", "groupkfold", "--dataset", $Dataset, "--all_folds", "--n_folds", "$NFolds", "--epochs", "$epochs")
        return
    }

    foreach ($fold in $GroupFolds) {
        if ($hasSampleFrac -and -not $NoSampleFrac) {
            RunPy $relPath @("--split_mode", "groupkfold", "--dataset", $Dataset, "--fold", "$fold", "--n_folds", "$NFolds", "--epochs", "$epochs", "--sample_frac", "$SampleFrac")
            continue
        }
        RunPy $relPath @("--split_mode", "groupkfold", "--dataset", $Dataset, "--fold", "$fold", "--n_folds", "$NFolds", "--epochs", "$epochs")
    }
}

Write-Host "=== COWRIE_FULL orchestration ===" -ForegroundColor Green
Write-Host "Repo root : $repoRoot"
Write-Host "Python    : $PythonExe"
Write-Host "Dataset   : $Dataset"
Write-Host "Modes     : $($Modes -join ', ')"
Write-Host "Window    : $WindowSize"
Write-Host "Dry run   : $DryRun"

if (-not $SkipPreprocess) {
    $prepareParams = @(
        "--dataset", $Dataset,
        "--window_size", $WindowSize,
        "--seed", "$Seed",
        "--n_folds", "$NFolds",
        "--min_multiclass_windows", "$MinMulticlassWindows",
        "--failed_login_threshold", "$FailedLoginThreshold",
        "--split_mode"
    )
    $prepareParams += $Modes
    if ($AllGroupFolds) {
        $prepareParams += "--all_folds"
    }
    elseif ($Modes -contains "groupkfold") {
        $prepareParams += @("--fold", "$($GroupFolds[0])")
    }
    RunPy "src\models\COWRIE_FULL\prepare_dataset.py" $prepareParams
}

foreach ($mode in $Modes) {
    if ($mode -eq "groupkfold") {
        if (-not $SkipBinaryHgb) {
            Invoke-GroupedTrainer "src\models\COWRIE_FULL\train_ml_binary_hgb.py" $BinaryEpochs
        }
        if (-not $SkipMulticlass) {
            Invoke-GroupedTrainer "src\models\COWRIE_FULL\train_ml_multiclass_hgb.py" $MulticlassEpochs
        }
        if (-not $SkipAnomaly) {
            Invoke-GroupedTrainer "src\models\COWRIE_FULL\train_anomaly_isoforest.py" $AnomalyEstimators -NoSampleFrac
        }
        continue
    }

    if (-not $SkipBinaryHgb) {
        RunPy "src\models\COWRIE_FULL\train_ml_binary_hgb.py" (New-TrainerParams $mode $BinaryEpochs)
    }
    if (-not $SkipMulticlass) {
        RunPy "src\models\COWRIE_FULL\train_ml_multiclass_hgb.py" (New-TrainerParams $mode $MulticlassEpochs)
    }
    if (-not $SkipAnomaly) {
        RunPy "src\models\COWRIE_FULL\train_anomaly_isoforest.py" @("--split_mode", $mode, "--dataset", $Dataset, "--epochs", "$AnomalyEstimators", "--n_jobs", "$AnomalyNJobs")
    }
}

if (-not $SkipCompare) {
    RunPy "src\models\COWRIE_FULL\compare_models.py" @("--artifacts_dir", (Join-Path $repoRoot "src\models\COWRIE_FULL\artifacts"))
}

Write-Host "`nCOWRIE_FULL orchestration finished." -ForegroundColor Green
