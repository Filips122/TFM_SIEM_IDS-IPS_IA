param(
    [ValidateSet("all", "CIC-IDS2017", "UNSW-NB15", "UGR16", "LAB-ALERTS", "COWRIE_FULL", "CSR-LANL")]
    [string[]]$Datasets = @("all"),

    [ValidateSet("fast", "balanced", "conservative", "expressive")]
    [string]$Profile = "balanced",

    [string]$PythonExe = ".\.venv\Scripts\python.exe",
    [Nullable[double]]$SampleFrac = $null,
    [int]$Fold = -1,
    [int]$NFolds = 5,
    [int]$Seed = 42,
    [int]$NJobs = 1,

    [switch]$AllFolds,
    [switch]$DryRun,
    [switch]$SkipHgb,
    [switch]$IncludeNeural,
    [switch]$IncludeAnomaly,
    [switch]$IncludeMulticlass,
    [switch]$IncludeStressSplits,
    [switch]$IncludeCsrHgb,
    [switch]$ClassWeightBalanced
)

$ErrorActionPreference = "Stop"
$InvariantCulture = [System.Globalization.CultureInfo]::InvariantCulture
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path

function Convert-ArgumentValue {
    param([object]$Value)
    if ($null -eq $Value) {
        return $null
    }
    if ($Value -is [double] -or $Value -is [float] -or $Value -is [decimal]) {
        return $Value.ToString("G", $InvariantCulture)
    }
    return [string]$Value
}

function Resolve-PythonExe {
    if (Test-Path $PythonExe) {
        return (Resolve-Path $PythonExe).Path
    }
    $candidate = Join-Path $RepoRoot $PythonExe
    if (Test-Path $candidate) {
        return (Resolve-Path $candidate).Path
    }
    return $PythonExe
}

$ResolvedPythonExe = Resolve-PythonExe

function Invoke-PythonScript {
    param(
        [string]$RelativeScript,
        [string[]]$Arguments
    )
    $scriptPath = Join-Path $RepoRoot $RelativeScript
    if (-not (Test-Path $scriptPath)) {
        throw "Script not found: $scriptPath"
    }
    $displayCommand = @($ResolvedPythonExe, "-u", $scriptPath) + $Arguments
    Write-Host ("[train] " + ($displayCommand -join " "))
    if ($DryRun) {
        return
    }
    & $ResolvedPythonExe -u $scriptPath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Training command failed with exit code $LASTEXITCODE"
    }
}

function Add-OptionalValueArgument {
    param(
        [string[]]$Arguments,
        [string]$Name,
        [object]$Value
    )
    if ($null -ne $Value) {
        return @($Arguments + @($Name, (Convert-ArgumentValue $Value)))
    }
    return @($Arguments)
}

function Add-SampleArguments {
    param([string[]]$Arguments)
    return Add-OptionalValueArgument -Arguments $Arguments -Name "--sample_frac" -Value $SampleFrac
}

function Add-GroupFoldArguments {
    param(
        [string[]]$Arguments,
        [int]$DefaultFold
    )
    if ($AllFolds) {
        return @($Arguments + @("--all_folds", "--n_folds", (Convert-ArgumentValue $NFolds)))
    }
    $foldToUse = $DefaultFold
    if ($Fold -ge 0) {
        $foldToUse = $Fold
    }
    return @($Arguments + @("--fold", (Convert-ArgumentValue $foldToUse)))
}

function Get-HgbProfileArguments {
    switch ($Profile) {
        "fast" {
            $arguments = @("--max_iter", "160", "--learning_rate", "0.08", "--max_depth", "3", "--max_leaf_nodes", "31", "--min_samples_leaf", "80", "--l2_regularization", "0.1", "--validation_fraction", "0.15", "--n_iter_no_change", "8")
        }
        "conservative" {
            $arguments = @("--max_iter", "700", "--learning_rate", "0.03", "--max_depth", "2", "--max_leaf_nodes", "31", "--min_samples_leaf", "100", "--l2_regularization", "1.0", "--validation_fraction", "0.2", "--n_iter_no_change", "16")
        }
        "expressive" {
            $arguments = @("--max_iter", "700", "--learning_rate", "0.035", "--max_depth", "4", "--max_leaf_nodes", "63", "--min_samples_leaf", "40", "--l2_regularization", "0.05", "--validation_fraction", "0.15", "--n_iter_no_change", "16")
        }
        default {
            $arguments = @("--max_iter", "500", "--learning_rate", "0.05", "--max_depth", "3", "--max_leaf_nodes", "31", "--min_samples_leaf", "50", "--l2_regularization", "0.1", "--validation_fraction", "0.15", "--n_iter_no_change", "12")
        }
    }
    if ($ClassWeightBalanced) {
        $arguments += @("--class_weight", "balanced")
    }
    return @($arguments + @("--seed", (Convert-ArgumentValue $Seed)))
}

function Get-MlpProfileArguments {
    switch ($Profile) {
        "fast" {
            return @("--epochs", "20", "--hidden", "256", "--depth", "2", "--dropout", "0.25", "--weight_decay", "0.0005", "--patience", "6", "--batch_size", "8192", "--lr", "0.001")
        }
        "conservative" {
            return @("--epochs", "80", "--hidden", "256", "--depth", "2", "--dropout", "0.35", "--weight_decay", "0.0005", "--patience", "10", "--batch_size", "8192", "--lr", "0.0007")
        }
        "expressive" {
            return @("--epochs", "80", "--hidden", "768", "--depth", "4", "--dropout", "0.25", "--weight_decay", "0.0001", "--patience", "10", "--batch_size", "8192", "--lr", "0.0008")
        }
        default {
            return @("--epochs", "60", "--hidden", "512", "--depth", "3", "--dropout", "0.25", "--weight_decay", "0.0001", "--patience", "8", "--batch_size", "8192", "--lr", "0.001")
        }
    }
}

function Get-GruProfileArguments {
    switch ($Profile) {
        "fast" {
            return @("--epochs", "20", "--hidden", "96", "--layers", "1", "--dropout", "0.2", "--weight_decay", "0.0005", "--patience", "6", "--batch_size", "2048", "--lr", "0.001")
        }
        "conservative" {
            return @("--epochs", "60", "--hidden", "128", "--layers", "2", "--dropout", "0.35", "--weight_decay", "0.0005", "--patience", "10", "--batch_size", "2048", "--lr", "0.0007")
        }
        "expressive" {
            return @("--epochs", "70", "--hidden", "192", "--layers", "3", "--dropout", "0.3", "--weight_decay", "0.0002", "--patience", "10", "--batch_size", "2048", "--lr", "0.0008", "--bidirectional")
        }
        default {
            return @("--epochs", "50", "--hidden", "128", "--layers", "2", "--dropout", "0.25", "--weight_decay", "0.0002", "--patience", "8", "--batch_size", "2048", "--lr", "0.001")
        }
    }
}

function Get-IsoForestProfileArguments {
    switch ($Profile) {
        "fast" {
            return @("--n_estimators", "250", "--max_samples", "100000", "--contamination", "auto", "--max_features", "0.9", "--n_jobs", (Convert-ArgumentValue $NJobs), "--seed", (Convert-ArgumentValue $Seed))
        }
        "conservative" {
            return @("--n_estimators", "700", "--max_samples", "auto", "--contamination", "auto", "--max_features", "0.8", "--n_jobs", (Convert-ArgumentValue $NJobs), "--seed", (Convert-ArgumentValue $Seed))
        }
        "expressive" {
            return @("--n_estimators", "900", "--max_samples", "auto", "--contamination", "auto", "--max_features", "1.0", "--n_jobs", (Convert-ArgumentValue $NJobs), "--seed", (Convert-ArgumentValue $Seed))
        }
        default {
            return @("--n_estimators", "500", "--max_samples", "auto", "--contamination", "auto", "--max_features", "1.0", "--n_jobs", (Convert-ArgumentValue $NJobs), "--seed", (Convert-ArgumentValue $Seed))
        }
    }
}

function Invoke-HgbTunable {
    param(
        [string]$DatasetKey,
        [string]$Pipeline,
        [string]$SplitMode,
        [int]$DefaultFold = -1,
        [string]$DatasetName = $null,
        [string]$DatasetsBase = $null,
        [switch]$ForceBalanced
    )
    $arguments = @("--dataset_key", $DatasetKey, "--pipeline", $Pipeline, "--split_mode", $SplitMode)
    $arguments += Get-HgbProfileArguments
    if ($ForceBalanced -and -not ($arguments -contains "--class_weight")) {
        $arguments += @("--class_weight", "balanced")
    }
    $arguments = Add-SampleArguments -Arguments $arguments
    if ($null -ne $DatasetName -and $DatasetName.Length -gt 0) {
        $arguments += @("--dataset", $DatasetName)
    }
    if ($null -ne $DatasetsBase -and $DatasetsBase.Length -gt 0) {
        $arguments += @("--datasets_base", $DatasetsBase)
    }
    if ($SplitMode -in @("groupkfold", "redteam_stratified_groupkfold")) {
        $arguments = Add-GroupFoldArguments -Arguments $arguments -DefaultFold $DefaultFold
    }
    Invoke-PythonScript -RelativeScript "src\models\common\train_hgb_tunable.py" -Arguments $arguments
}

function Invoke-IsoForestTunable {
    param(
        [string]$DatasetKey,
        [string]$SplitMode,
        [int]$DefaultFold = -1,
        [string]$DatasetName = $null,
        [string]$DatasetsBase = $null
    )
    $arguments = @("--dataset_key", $DatasetKey, "--split_mode", $SplitMode)
    $arguments += Get-IsoForestProfileArguments
    $arguments = Add-SampleArguments -Arguments $arguments
    if ($null -ne $DatasetName -and $DatasetName.Length -gt 0) {
        $arguments += @("--dataset", $DatasetName)
    }
    if ($null -ne $DatasetsBase -and $DatasetsBase.Length -gt 0) {
        $arguments += @("--datasets_base", $DatasetsBase)
    }
    if ($SplitMode -in @("groupkfold", "redteam_stratified_groupkfold")) {
        $arguments = Add-GroupFoldArguments -Arguments $arguments -DefaultFold $DefaultFold
    }
    Invoke-PythonScript -RelativeScript "src\models\common\train_isoforest_tunable.py" -Arguments $arguments
}

function Invoke-ExistingMlp {
    param(
        [string]$RelativeScript,
        [string]$SplitMode = $null,
        [int]$DefaultFold = -1,
        [string]$DatasetName = $null,
        [bool]$SupportsSampleFrac = $true
    )
    $arguments = Get-MlpProfileArguments
    $arguments += @("--seed", (Convert-ArgumentValue $Seed))
    if ($SupportsSampleFrac) {
        $arguments = Add-SampleArguments -Arguments $arguments
    }
    if ($null -ne $SplitMode -and $SplitMode.Length -gt 0) {
        $arguments += @("--split_mode", $SplitMode)
        if ($SplitMode -eq "groupkfold") {
            $arguments = Add-GroupFoldArguments -Arguments $arguments -DefaultFold $DefaultFold
        }
    }
    if ($null -ne $DatasetName -and $DatasetName.Length -gt 0) {
        $arguments += @("--dataset", $DatasetName)
    }
    Invoke-PythonScript -RelativeScript $RelativeScript -Arguments $arguments
}

function Invoke-CicGru {
    param([string]$Mode, [int]$DefaultFold = -1)
    $arguments = @("--mode", $Mode, "--task", "binary")
    $arguments += Get-GruProfileArguments
    $arguments += @("--seed", (Convert-ArgumentValue $Seed), "--max_eval_samples", "200000")
    if ($Mode -eq "groupkfold") {
        $arguments = Add-GroupFoldArguments -Arguments $arguments -DefaultFold $DefaultFold
    }
    Invoke-PythonScript -RelativeScript "src\models\CIC-IDS2017\train_seq_tl_gru.py" -Arguments $arguments
}

function Train-CicIds2017 {
    if (-not $SkipHgb) {
        Invoke-HgbTunable -DatasetKey "CIC-IDS2017" -Pipeline "binary" -SplitMode "day"
        if ($IncludeStressSplits) {
            Invoke-HgbTunable -DatasetKey "CIC-IDS2017" -Pipeline "binary" -SplitMode "groupkfold" -DefaultFold 4
        }
    }
    if ($IncludeMulticlass) {
        Invoke-HgbTunable -DatasetKey "CIC-IDS2017" -Pipeline "multiclass" -SplitMode "day"
    }
    if ($IncludeNeural) {
        Invoke-ExistingMlp -RelativeScript "src\models\CIC-IDS2017\train_ml_binary_mlp.py" -SupportsSampleFrac $false
        Invoke-CicGru -Mode "day"
        if ($IncludeStressSplits) {
            Invoke-CicGru -Mode "groupkfold" -DefaultFold 4
        }
    }
    if ($IncludeAnomaly) {
        Invoke-IsoForestTunable -DatasetKey "CIC-IDS2017" -SplitMode "day"
    }
}

function Train-UnswNb15 {
    if (-not $SkipHgb) {
        Invoke-HgbTunable -DatasetKey "UNSW-NB15" -Pipeline "binary" -SplitMode "groupkfold" -DefaultFold 0
        if ($IncludeStressSplits) {
            Invoke-HgbTunable -DatasetKey "UNSW-NB15" -Pipeline "binary" -SplitMode "official"
        }
    }
    if ($IncludeMulticlass) {
        Invoke-HgbTunable -DatasetKey "UNSW-NB15" -Pipeline "multiclass" -SplitMode "groupkfold" -DefaultFold 0
    }
    if ($IncludeNeural) {
        Invoke-ExistingMlp -RelativeScript "src\models\UNSW-NB15\train_ml_binary_mlp.py" -SplitMode "groupkfold" -DefaultFold 0
        if ($IncludeStressSplits) {
            Invoke-ExistingMlp -RelativeScript "src\models\UNSW-NB15\train_ml_binary_mlp.py" -SplitMode "official"
        }
    }
    if ($IncludeAnomaly) {
        Invoke-IsoForestTunable -DatasetKey "UNSW-NB15" -SplitMode "groupkfold" -DefaultFold 0
    }
}

function Train-Ugr16 {
    $datasetName = "UGR16_MARAPR_HYBRID"
    if (-not $SkipHgb) {
        Invoke-HgbTunable -DatasetKey "UGR16" -Pipeline "binary" -SplitMode "date" -DatasetName $datasetName
        if ($IncludeStressSplits) {
            Invoke-HgbTunable -DatasetKey "UGR16" -Pipeline "binary" -SplitMode "groupkfold" -DefaultFold 0 -DatasetName $datasetName
        }
    }
    if ($IncludeMulticlass) {
        Invoke-HgbTunable -DatasetKey "UGR16" -Pipeline "multiclass" -SplitMode "date" -DatasetName $datasetName
    }
    if ($IncludeNeural) {
        Invoke-ExistingMlp -RelativeScript "src\models\UGR16\train_ml_binary_mlp.py" -SplitMode "date" -DatasetName $datasetName
    }
    if ($IncludeAnomaly) {
        Invoke-IsoForestTunable -DatasetKey "UGR16" -SplitMode "date" -DatasetName $datasetName
    }
}

function Train-LabAlerts {
    if (-not $SkipHgb) {
        Invoke-HgbTunable -DatasetKey "LAB-ALERTS" -Pipeline "binary" -SplitMode "date"
    }
    if ($IncludeMulticlass) {
        Invoke-HgbTunable -DatasetKey "LAB-ALERTS" -Pipeline "multiclass" -SplitMode "date"
    }
    if ($IncludeAnomaly) {
        Invoke-IsoForestTunable -DatasetKey "LAB-ALERTS" -SplitMode "date"
    }
}

function Train-CowrieFull {
    if (-not $SkipHgb) {
        Invoke-HgbTunable -DatasetKey "COWRIE_FULL" -Pipeline "multiclass" -SplitMode "date"
    }
    if ($IncludeMulticlass) {
        Invoke-HgbTunable -DatasetKey "COWRIE_FULL" -Pipeline "binary" -SplitMode "date"
    }
    if ($IncludeAnomaly) {
        Invoke-IsoForestTunable -DatasetKey "COWRIE_FULL" -SplitMode "date"
    }
}

function Train-CsrLanl {
    Invoke-IsoForestTunable -DatasetKey "CSR-LANL" -SplitMode "redteam_stratified_groupkfold" -DefaultFold 0
    if ($IncludeCsrHgb -and -not $SkipHgb) {
        Invoke-HgbTunable -DatasetKey "CSR-LANL" -Pipeline "binary" -SplitMode "redteam_stratified_groupkfold" -DefaultFold 0 -ForceBalanced
    }
}

function Expand-DatasetSelection {
    $allDatasets = @("CIC-IDS2017", "UNSW-NB15", "UGR16", "LAB-ALERTS", "COWRIE_FULL", "CSR-LANL")
    if ($Datasets -contains "all") {
        return $allDatasets
    }
    return $Datasets
}

Write-Host "Training profile: $Profile"
Write-Host "Python: $ResolvedPythonExe"
Write-Host "Repository: $RepoRoot"
if ($DryRun) {
    Write-Host "Dry run enabled: commands will be printed only."
}

foreach ($datasetKey in (Expand-DatasetSelection)) {
    Write-Host ""
    Write-Host "=== $datasetKey ==="
    switch ($datasetKey) {
        "CIC-IDS2017" { Train-CicIds2017 }
        "UNSW-NB15" { Train-UnswNb15 }
        "UGR16" { Train-Ugr16 }
        "LAB-ALERTS" { Train-LabAlerts }
        "COWRIE_FULL" { Train-CowrieFull }
        "CSR-LANL" { Train-CsrLanl }
        default { throw "Unsupported dataset: $datasetKey" }
    }
}

Write-Host ""
Write-Host "Training commands completed."