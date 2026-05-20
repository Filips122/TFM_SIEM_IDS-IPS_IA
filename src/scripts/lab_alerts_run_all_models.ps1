param(
    [string[]]$Modes = @("date"),
    [string]$Dataset = "LAB-ALERTS",
    [string]$PythonExe = "python",
    [string]$WindowSize = "1min",
    [int]$Seed = 42,
    [int]$NFolds = 5,
    [int[]]$GroupFolds = @(0),
    [int]$BinaryEpochs = 215,
    [int]$MulticlassEpochs = 215,
    [int]$AnomalyEstimators = 315,
    [int]$MinMulticlassWindows = 30,
    [ValidateSet("full", "operational_no_label_proxy")]
    [string]$FeatureProfile = "full",
    [double]$SampleFrac,
    [switch]$AllGroupFolds,
    [switch]$SkipPreprocess,
    [switch]$SkipBinaryHgb,
    [switch]$SkipMulticlass,
    [switch]$SkipAnomaly,
    [switch]$SkipCompare
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

function RunPy([string]$relPath, [string[]]$pyArgs) {
    $fullPath = Join-Path $repoRoot $relPath
    if (!(Test-Path $fullPath)) {
        throw "No existe el script: $fullPath"
    }
    Write-Host "`n>>> python -u $relPath $($pyArgs -join ' ')" -ForegroundColor Cyan
    & $PythonExe -u $fullPath @pyArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Fallo: $relPath (exit code $LASTEXITCODE)"
    }
}

function New-TrainerArgs([string]$mode, [int]$epochs) {
    $args = @("--split_mode", $mode, "--dataset", $Dataset, "--epochs", "$epochs")
    if ($hasSampleFrac) {
        $args += @("--sample_frac", "$SampleFrac")
    }
    return $args
}

function Invoke-GroupedTrainer([string]$relPath, [int]$epochs, [switch]$NoSampleFrac) {
    if ($AllGroupFolds) {
        $args = @("--split_mode", "groupkfold", "--dataset", $Dataset, "--all_folds", "--n_folds", "$NFolds", "--epochs", "$epochs")
        if ($hasSampleFrac -and -not $NoSampleFrac) {
            $args += @("--sample_frac", "$SampleFrac")
        }
        RunPy $relPath $args
        return
    }

    foreach ($fold in $GroupFolds) {
        $args = @("--split_mode", "groupkfold", "--dataset", $Dataset, "--fold", "$fold", "--n_folds", "$NFolds", "--epochs", "$epochs")
        if ($hasSampleFrac -and -not $NoSampleFrac) {
            $args += @("--sample_frac", "$SampleFrac")
        }
        RunPy $relPath $args
    }
}

Write-Host "=== LAB-ALERTS orchestration ===" -ForegroundColor Green
Write-Host "Repo root : $repoRoot"
Write-Host "Python    : $PythonExe"
Write-Host "Dataset   : $Dataset"
Write-Host "Modes     : $($Modes -join ', ')"
Write-Host "Features  : $FeatureProfile"

if (-not $SkipPreprocess) {
    $prepareArgs = @("--dataset", $Dataset, "--window_size", $WindowSize, "--seed", "$Seed", "--n_folds", "$NFolds", "--min_multiclass_windows", "$MinMulticlassWindows", "--feature_profile", $FeatureProfile, "--split_mode")
    $prepareArgs += $Modes
    if ($AllGroupFolds) {
        $prepareArgs += "--all_folds"
    }
    elseif ($Modes -contains "groupkfold") {
        $prepareArgs += @("--fold", "$($GroupFolds[0])")
    }
    RunPy "src\models\LAB-ALERTS\prepare_dataset.py" $prepareArgs
}

foreach ($mode in $Modes) {
    if ($mode -eq "groupkfold") {
        if (-not $SkipBinaryHgb) {
            Invoke-GroupedTrainer "src\models\LAB-ALERTS\train_ml_binary_hgb.py" $BinaryEpochs
        }
        if (-not $SkipMulticlass) {
            Invoke-GroupedTrainer "src\models\LAB-ALERTS\train_ml_multiclass_hgb.py" $MulticlassEpochs
        }
        if (-not $SkipAnomaly) {
            Invoke-GroupedTrainer "src\models\LAB-ALERTS\train_anomaly_isoforest.py" $AnomalyEstimators -NoSampleFrac
        }
        continue
    }

    if (-not $SkipBinaryHgb) {
        RunPy "src\models\LAB-ALERTS\train_ml_binary_hgb.py" (New-TrainerArgs $mode $BinaryEpochs)
    }
    if (-not $SkipMulticlass) {
        RunPy "src\models\LAB-ALERTS\train_ml_multiclass_hgb.py" (New-TrainerArgs $mode $MulticlassEpochs)
    }
    if (-not $SkipAnomaly) {
        RunPy "src\models\LAB-ALERTS\train_anomaly_isoforest.py" @("--split_mode", $mode, "--dataset", $Dataset, "--epochs", "$AnomalyEstimators")
    }
}

if (-not $SkipCompare) {
    $compareArgs = @("--artifacts_dir", (Join-Path $repoRoot "src\models\LAB-ALERTS\artifacts"), "--split_modes") + $Modes
    RunPy "src\models\LAB-ALERTS\compare_models.py" $compareArgs
}

Write-Host "`nLAB-ALERTS orchestration finished." -ForegroundColor Green