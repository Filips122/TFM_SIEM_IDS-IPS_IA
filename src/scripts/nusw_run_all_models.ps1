param(
    [string[]]$Modes = @("random", "groupkfold", "official"),

    [ValidateSet("raw4", "official_pair", "all")]
    [string]$SourceSet = "raw4",

    [ValidateSet("strict", "fallback_official_benign")]
    [string]$AnomalyGroupTrainPolicy = "strict",

    [string]$PythonExe = "python",
    [int]$Chunksize = 250000,
    [int]$Seed = 42,
    [int]$BinaryEpochs = 215,
    [int]$MulticlassEpochs = 265,
    [int]$AnomalyEstimators = 315,
    [int]$MlpEpochs = 40,
    [int]$NFolds = 8,
    [int[]]$GroupFolds = @(0),
    [double]$SampleFrac,
    [switch]$AllGroupFolds,
    [switch]$RunAnalysis,
    [switch]$SkipBinaryHgb,
    [switch]$SkipMulticlass,
    [switch]$SkipAnomaly,
    [switch]$SkipBinaryMlp,
    [switch]$DeepAnalysis,
    [switch]$SkipPreprocess,
    [switch]$SkipValidation,
    [switch]$SkipCompare,
    [switch]$CleanDatasets,
    [switch]$HashInputs,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$allowedModes = @("random", "groupkfold", "official")
$normalizedModes = @()
foreach ($modeArg in $Modes) {
    $parts = @($modeArg -split ",")
    foreach ($part in $parts) {
        $candidate = $part.Trim().ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($candidate)) {
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
    throw "At least one mode is required. Allowed values: $($allowedModes -join ', ')"
}

# Script location (usually <repo>\src\scripts)
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Repo root assumed: src\scripts -> ..\..
$repoRoot = Resolve-Path (Join-Path $scriptDir "..\..")
$venvPython = Join-Path $repoRoot ".venv\Scripts\python.exe"
if ($PythonExe -eq "python" -and (Test-Path $venvPython)) {
    $PythonExe = $venvPython
}
$hasSampleFrac = $PSBoundParameters.ContainsKey("SampleFrac")

function RunPy([string]$relPath, [string[]]$pythonParams) {
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

function Invoke-Prepare([string]$mode) {
    $prepareSourceSet = if ($mode -eq "official") { "official_pair" } else { $SourceSet }
    $prepareParams = @(
        "--split_mode", $mode,
        "--source_set", $prepareSourceSet,
        "--anomaly_group_train_policy", $AnomalyGroupTrainPolicy,
        "--chunksize", "$Chunksize",
        "--seed", "$Seed"
    )

    if ($CleanDatasets) {
        $prepareParams += "--clean"
    }
    if ($HashInputs) {
        $prepareParams += "--hash_inputs"
    }

    if ($mode -eq "groupkfold") {
        if ($AllGroupFolds) {
            $prepareParams += @("--all_folds", "--n_folds", "$NFolds")
        }
        else {
            foreach ($fold in $GroupFolds) {
                RunPy "src\models\UNSW-NB15\prepare_dataset.py" ($prepareParams + @("--fold", "$fold", "--n_folds", "$NFolds"))
            }
            return
        }
    }

    RunPy "src\models\UNSW-NB15\prepare_dataset.py" $prepareParams
}

function Invoke-GroupedTrainer([string]$relPath, [string]$epochsFlag, [int]$epochsValue) {
    if ($AllGroupFolds) {
        $trainerParams = @("--split_mode", "groupkfold", "--all_folds", "--n_folds", "$NFolds", $epochsFlag, "$epochsValue")
        if ($hasSampleFrac) {
            $trainerParams += @("--sample_frac", "$SampleFrac")
        }
        RunPy $relPath $trainerParams
        return
    }

    foreach ($fold in $GroupFolds) {
        $trainerParams = @("--split_mode", "groupkfold", "--fold", "$fold", "--n_folds", "$NFolds", $epochsFlag, "$epochsValue")
        if ($hasSampleFrac) {
            $trainerParams += @("--sample_frac", "$SampleFrac")
        }
        RunPy $relPath $trainerParams
    }
}

function Invoke-GroupedAnomalyTrainer() {
    if ($AllGroupFolds) {
        RunPy "src\models\UNSW-NB15\train_anomaly_isoforest.py" @(
            "--split_mode", "groupkfold",
            "--all_folds",
            "--n_folds", "$NFolds",
            "--epochs", "$AnomalyEstimators"
        )
        return
    }

    foreach ($fold in $GroupFolds) {
        RunPy "src\models\UNSW-NB15\train_anomaly_isoforest.py" @(
            "--split_mode", "groupkfold",
            "--fold", "$fold",
            "--n_folds", "$NFolds",
            "--epochs", "$AnomalyEstimators"
        )
    }
}

Write-Host "=== UNSW-NB15 orchestration ===" -ForegroundColor Green
Write-Host "Repo root : $repoRoot"
Write-Host "Python    : $PythonExe"
Write-Host "Modes     : $($Modes -join ', ')"
Write-Host "Source set: $SourceSet"
Write-Host "Anomaly policy: $AnomalyGroupTrainPolicy"
Write-Host "Run binary HGB: $(-not $SkipBinaryHgb)"
Write-Host "Run multiclass HGB: $(-not $SkipMulticlass)"
Write-Host "Run anomaly model: $(-not $SkipAnomaly)"
Write-Host "Run binary MLP: $(-not $SkipBinaryMlp)"

if ($RunAnalysis) {
    $analysisParams = @()
    if ($DeepAnalysis) {
        $analysisParams += "--deep"
    }
    RunPy "src\helpers\analyze_nusw_folder.py" $analysisParams
}

if (-not $SkipPreprocess) {
    foreach ($mode in $Modes) {
        Invoke-Prepare $mode
    }
}

if (-not $SkipValidation) {
    $validationParams = @("--modes") + $Modes + @("--label_map_scope", "none")
    if (($Modes -contains "groupkfold") -and (-not $AllGroupFolds)) {
        $validationParams += @("--folds") + @($GroupFolds | ForEach-Object { "$($_)" })
    }
    RunPy "src\models\UNSW-NB15\validate_datasets.py" $validationParams
}

foreach ($mode in $Modes) {
    if ($mode -eq "groupkfold") {
        if (-not $SkipBinaryHgb) {
            Invoke-GroupedTrainer "src\models\UNSW-NB15\train_ml_binary_hgb.py" "--epochs" $BinaryEpochs
        }
        if (-not $SkipMulticlass) {
            Invoke-GroupedTrainer "src\models\UNSW-NB15\train_ml_multiclass_hgb.py" "--epochs" $MulticlassEpochs
        }
        if (-not $SkipBinaryMlp) {
            Invoke-GroupedTrainer "src\models\UNSW-NB15\train_ml_binary_mlp.py" "--epochs" $MlpEpochs
        }
        if (-not $SkipAnomaly) {
            Invoke-GroupedAnomalyTrainer
        }
        continue
    }

    $binaryParams = @("--split_mode", $mode, "--epochs", "$BinaryEpochs")
    $multiclassParams = @("--split_mode", $mode, "--epochs", "$MulticlassEpochs")
    if ($hasSampleFrac) {
        $binaryParams += @("--sample_frac", "$SampleFrac")
        $multiclassParams += @("--sample_frac", "$SampleFrac")
    }

    if (-not $SkipBinaryHgb) {
        RunPy "src\models\UNSW-NB15\train_ml_binary_hgb.py" $binaryParams
    }
    if (-not $SkipMulticlass) {
        RunPy "src\models\UNSW-NB15\train_ml_multiclass_hgb.py" $multiclassParams
    }
    if (-not $SkipBinaryMlp) {
        $mlpParams = @("--split_mode", $mode, "--epochs", "$MlpEpochs")
        if ($hasSampleFrac) {
            $mlpParams += @("--sample_frac", "$SampleFrac")
        }
        RunPy "src\models\UNSW-NB15\train_ml_binary_mlp.py" $mlpParams
    }
    if (-not $SkipAnomaly) {
        RunPy "src\models\UNSW-NB15\train_anomaly_isoforest.py" @("--split_mode", $mode, "--epochs", "$AnomalyEstimators")
    }
}

if (-not $SkipCompare) {
    RunPy "src\models\UNSW-NB15\compare_models.py" @(
        "--artifacts_dir", (Join-Path $repoRoot "src\models\UNSW-NB15\artifacts")
    )
}

Write-Host "`nUNSW-NB15 orchestration finished." -ForegroundColor Green