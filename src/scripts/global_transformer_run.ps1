param(
    [ValidateSet("prepare", "train", "all")]
    [string]$Stage = "prepare",

    [ValidateSet("fast", "balanced", "conservative")]
    [string]$Profile = "balanced",

    [ValidateSet("all", "CIC-IDS2017", "UNSW-NB15", "UGR16", "LAB-ALERTS", "COWRIE_FULL")]
    [string[]]$Datasets = @("all"),

    [string]$PythonExe = ".\.venv\Scripts\python.exe",
    [string]$OutputRoot = "src/models/GLOBAL_TRANSFORMER/datasets/GLOBAL_BINARY_V1",
    [string]$ArtifactRoot = "src/models/GLOBAL_TRANSFORMER/artifacts",
    [string]$Version = "GLOBAL_BINARY_V1",
    [ValidateSet("", "ALL", "CIC-IDS2017", "UNSW-NB15", "UGR16", "LAB-ALERTS", "COWRIE_FULL")]
    [string]$HoldoutDataset = "",
    [Nullable[double]]$SampleFrac = $null,
    [int]$MaxRowsPerDataset = 200000,
    [int]$Seed = 42,
    [int]$Epochs = 0,
    [int]$BatchSize = 0,
    [switch]$Overwrite,
    [switch]$DryRun,
    [switch]$DisableDatasetEmbedding
)

$ErrorActionPreference = "Stop"
$InvariantCulture = [System.Globalization.CultureInfo]::InvariantCulture
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path

function Convert-ArgumentValue {
    param([object]$Value)
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
$KnownHoldoutDatasets = @("CIC-IDS2017", "UNSW-NB15", "UGR16", "LAB-ALERTS", "COWRIE_FULL")

function Invoke-Prepare {
    $scriptPath = Join-Path $RepoRoot "src\models\GLOBAL_TRANSFORMER\prepare_global_dataset.py"
    $arguments = @(
        "--datasets"
    )
    foreach ($dataset in $Datasets) {
        $arguments += $dataset
    }
    $arguments += @(
        "--output_root", $OutputRoot,
        "--max_rows_per_dataset", (Convert-ArgumentValue $MaxRowsPerDataset),
        "--seed", (Convert-ArgumentValue $Seed)
    )
    if ($null -ne $SampleFrac) {
        $arguments += @("--sample_frac", (Convert-ArgumentValue $SampleFrac))
    }
    if ($Overwrite) {
        $arguments += "--overwrite"
    }
    if ($DryRun) {
        $arguments += "--dry_run"
    }

    $displayCommand = @($ResolvedPythonExe, "-u", $scriptPath) + $arguments
    Write-Host ("[global-transformer] " + ($displayCommand -join " "))
    & $ResolvedPythonExe -u $scriptPath @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Global Transformer stage failed with exit code $LASTEXITCODE"
    }
}

function Invoke-TrainSingle {
    param([string]$SelectedHoldout)

    $scriptPath = Join-Path $RepoRoot "src\models\GLOBAL_TRANSFORMER\train_global_binary_transformer.py"
    $arguments = @(
        "--dataset_root", $OutputRoot,
        "--artifact_root", $ArtifactRoot,
        "--version", $Version,
        "--profile", $Profile,
        "--seed", (Convert-ArgumentValue $Seed)
    )
    if ($Epochs -gt 0) {
        $arguments += @("--epochs", (Convert-ArgumentValue $Epochs))
    }
    if ($BatchSize -gt 0) {
        $arguments += @("--batch_size", (Convert-ArgumentValue $BatchSize))
    }
    if ($SelectedHoldout.Length -gt 0) {
        $arguments += @("--holdout_dataset", $SelectedHoldout)
        if (-not $DisableDatasetEmbedding) {
            Write-Host "Holdout dataset selected: disabling dataset embedding for stricter unseen-domain evaluation."
        }
        $arguments += "--disable_dataset_embedding"
    }
    elseif ($DisableDatasetEmbedding) {
        $arguments += "--disable_dataset_embedding"
    }
    if ($DryRun) {
        $arguments += "--dry_run"
    }

    $displayCommand = @($ResolvedPythonExe, "-u", $scriptPath) + $arguments
    Write-Host ("[global-transformer] " + ($displayCommand -join " "))
    & $ResolvedPythonExe -u $scriptPath @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Global Transformer training failed with exit code $LASTEXITCODE"
    }
}

function Invoke-Train {
    if ($HoldoutDataset -eq "ALL") {
        foreach ($dataset in $KnownHoldoutDatasets) {
            Write-Host ""
            Write-Host "Running leave-one-dataset-out holdout: $dataset"
            Invoke-TrainSingle -SelectedHoldout $dataset
        }
        return
    }

    Invoke-TrainSingle -SelectedHoldout $HoldoutDataset
}

Write-Host "Global Transformer stage: $Stage"
Write-Host "Profile: $Profile"
Write-Host "Python: $ResolvedPythonExe"
Write-Host "Repository: $RepoRoot"

switch ($Stage) {
    "prepare" { Invoke-Prepare }
    "train" { Invoke-Train }
    "all" {
        Invoke-Prepare
        Invoke-Train
    }
    default { throw "Unsupported stage: $Stage" }
}

Write-Host "Global Transformer stage completed."