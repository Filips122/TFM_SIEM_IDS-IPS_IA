param(
    [string[]]$Datasets = @("all"),
    [string]$PythonExe = "python",
    [string[]]$NuswModes = @("random"),
    [string[]]$UgrModes = @("date"),
    [string[]]$LabModes = @("date"),
    [string[]]$CowrieModes = @("date"),
    [string[]]$CsrModes = @("random"),
    [string]$UgrDataset = "UGR16_MARAPR_HYBRID",
    [string]$LabDataset = "LAB-ALERTS",
    [string]$CowrieDataset = "COWRIE_FULL",
    [string]$CsrDataset = "CSR-LANL",
    [string]$CsrDatasetsBase = "src/models/CSR-LANL/datasets_subsample",
    [ValidateSet("full", "operational_no_label_proxy")]
    [string]$LabFeatureProfile = "full",
    [ValidateSet("full", "operational_no_label_proxy")]
    [string]$CowrieFeatureProfile = "full",
    [int]$CicEpochs = 20,
    [int]$BinaryEpochs = 215,
    [int]$MulticlassEpochs = 215,
    [int]$AnomalyEstimators = 315,
    [int]$UgrAnomalyMaxTrainRows = 500000,
    [int]$UgrAnomalyMaxEvalRows = 200000,
    [int]$UgrAnomalyNJobs = 1,
    [int]$MlpEpochs = 40,
    [int]$NuswNFolds = 8,
    [int]$UgrNFolds = 8,
    [int]$LabNFolds = 5,
    [int]$CowrieNFolds = 5,
    [int[]]$GroupFolds = @(0),
    [double]$SampleFrac,
    [switch]$RunPreprocess,
    [switch]$SkipValidation,
    [switch]$SkipDatasetCheck,
    [switch]$SkipBinaryHgb,
    [switch]$SkipMulticlass,
    [switch]$SkipAnomaly,
    [switch]$SkipMlp,
    [switch]$SkipCompare,
    [switch]$DryRun,
    [switch]$ContinueOnError
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptDir "..\..")
$venvPython = Join-Path $repoRoot ".venv\Scripts\python.exe"
$venvScripts = Split-Path -Parent $venvPython
if ($PythonExe -eq "python" -and (Test-Path $venvPython)) {
    $PythonExe = $venvPython
}
if (Test-Path $venvScripts) {
    $env:Path = "$venvScripts;$env:Path"
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
$hasSampleFrac = $PSBoundParameters.ContainsKey("SampleFrac")

function Resolve-DatasetSelection([string[]]$items) {
    $all = @("CIC-IDS2017", "UNSW-NB15", "UGR16", "LAB-ALERTS", "COWRIE_FULL", "CSR-LANL")
    $selected = @()
    foreach ($item in $items) {
        foreach ($part in @($item -split ",")) {
            $candidate = $part.Trim().ToUpperInvariant()
            if ([string]::IsNullOrWhiteSpace($candidate)) {
                continue
            }
            switch ($candidate) {
                "ALL" { $selected += $all }
                "CIC" { $selected += "CIC-IDS2017" }
                "CIC-IDS2017" { $selected += "CIC-IDS2017" }
                "UNSW" { $selected += "UNSW-NB15" }
                "UNSW-NB15" { $selected += "UNSW-NB15" }
                "NUSW" { $selected += "UNSW-NB15" }
                "NUSW-NB15" { $selected += "UNSW-NB15" }
                "UGR" { $selected += "UGR16" }
                "UGR16" { $selected += "UGR16" }
                "LAB" { $selected += "LAB-ALERTS" }
                "LAB-ALERTS" { $selected += "LAB-ALERTS" }
                "COWRIE" { $selected += "COWRIE_FULL" }
                "COWRIE_FULL" { $selected += "COWRIE_FULL" }
                "CSR" { $selected += "CSR-LANL" }
                "CSR-LANL" { $selected += "CSR-LANL" }
                default { throw "Invalid dataset '$part'. Use: all, CIC-IDS2017, UNSW-NB15, UGR16, LAB-ALERTS, COWRIE_FULL, CSR-LANL." }
            }
        }
    }
    return @($selected | Select-Object -Unique)
}

function RunScript([string]$label, [string]$relPath, [string[]]$scriptArgs) {
    $fullPath = Join-Path $repoRoot $relPath
    if (!(Test-Path $fullPath)) {
        throw "No existe el script: $fullPath"
    }

    Write-Host "`n=== $label ===" -ForegroundColor Green
    Write-Host ">>> $relPath $($scriptArgs -join ' ')" -ForegroundColor Cyan
    if ($DryRun) {
        return
    }

    & $powerShellExe -NoProfile -ExecutionPolicy Bypass -File $fullPath @scriptArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Fallo: $relPath (exit code $LASTEXITCODE)"
    }
}

function Invoke-Step([string]$label, [string]$relPath, [string[]]$scriptArgs) {
    try {
        RunScript $label $relPath $scriptArgs
    }
    catch {
        if (-not $ContinueOnError) {
            throw
        }
        Write-Warning "$label failed: $($_.Exception.Message)"
        $script:Failures += [pscustomobject]@{
            Dataset = $label
            Script = $relPath
            Error = $_.Exception.Message
        }
    }
}

function Add-CommonSkips([string[]]$ArgList, [switch]$SupportsMlp) {
    if ($SkipBinaryHgb) {
        $ArgList += "-SkipBinaryHgb"
    }
    if ($SkipMulticlass) {
        $ArgList += "-SkipMulticlass"
    }
    if ($SkipAnomaly) {
        $ArgList += "-SkipAnomaly"
    }
    if ($SkipMlp -and $SupportsMlp) {
        $ArgList += "-SkipBinaryMlp"
    }
    if ($SkipCompare) {
        $ArgList += "-SkipCompare"
    }
    if ($hasSampleFrac) {
        $ArgList += @("-SampleFrac", "$SampleFrac")
    }
    return $ArgList
}

$selectedDatasets = @(Resolve-DatasetSelection $Datasets)
if (-not $selectedDatasets -or $selectedDatasets.Count -eq 0) {
    throw "No datasets selected."
}

$Failures = @()

Write-Host "=== All dataset model training ===" -ForegroundColor Green
Write-Host "Repo root : $repoRoot"
Write-Host "Python    : $PythonExe"
Write-Host "Shell     : $powerShellExe"
Write-Host "Datasets  : $($selectedDatasets -join ', ')"
Write-Host "Dry run   : $DryRun"
Write-Host "Preprocess: $RunPreprocess"

foreach ($dataset in $selectedDatasets) {
    switch ($dataset) {
        "CIC-IDS2017" {
            $childArgs = @("-PythonExe", "$PythonExe", "-Epochs", "$CicEpochs")
            if ($SkipCompare) {
                $childArgs += "-SkipCompare"
            }
            Invoke-Step "CIC-IDS2017" "src\scripts\cic_run_all_models.ps1" $childArgs
        }
        "UNSW-NB15" {
            $childArgs = @(
                "-Modes"
            ) + $NuswModes + @(
                "-PythonExe", "$PythonExe",
                "-BinaryEpochs", "$BinaryEpochs",
                "-MulticlassEpochs", "$MulticlassEpochs",
                "-AnomalyEstimators", "$AnomalyEstimators",
                "-MlpEpochs", "$MlpEpochs",
                "-NFolds", "$NuswNFolds"
            )
            if (-not $RunPreprocess) {
                $childArgs += "-SkipPreprocess"
            }
            if ($SkipValidation) {
                $childArgs += "-SkipValidation"
            }
            $childArgs = Add-CommonSkips $childArgs -SupportsMlp
            Invoke-Step "UNSW-NB15" "src\scripts\nusw_run_all_models.ps1" $childArgs
        }
        "UGR16" {
            $childArgs = @(
                "-Modes"
            ) + $UgrModes + @(
                "-Dataset", "$UgrDataset",
                "-PythonExe", "$PythonExe",
                "-BinaryEpochs", "$BinaryEpochs",
                "-MulticlassEpochs", "$MulticlassEpochs",
                "-AnomalyEstimators", "$AnomalyEstimators",
                "-AnomalyMaxTrainRows", "$UgrAnomalyMaxTrainRows",
                "-AnomalyMaxEvalRows", "$UgrAnomalyMaxEvalRows",
                "-AnomalyNJobs", "$UgrAnomalyNJobs",
                "-MlpEpochs", "$MlpEpochs",
                "-NFolds", "$UgrNFolds"
            )
            if ($SkipDatasetCheck) {
                $childArgs += "-SkipDatasetCheck"
            }
            $childArgs = Add-CommonSkips $childArgs -SupportsMlp
            Invoke-Step "UGR16" "src\scripts\ugr_run_existing_dataset_models.ps1" $childArgs
        }
        "LAB-ALERTS" {
            $childArgs = @(
                "-Modes"
            ) + $LabModes + @(
                "-Dataset", "$LabDataset",
                "-PythonExe", "$PythonExe",
                "-BinaryEpochs", "$BinaryEpochs",
                "-MulticlassEpochs", "$MulticlassEpochs",
                "-AnomalyEstimators", "$AnomalyEstimators",
                "-NFolds", "$LabNFolds",
                "-FeatureProfile", "$LabFeatureProfile"
            )
            if (-not $RunPreprocess) {
                $childArgs += "-SkipPreprocess"
            }
            $childArgs = Add-CommonSkips $childArgs
            Invoke-Step "LAB-ALERTS" "src\scripts\lab_alerts_run_all_models.ps1" $childArgs
        }
        "COWRIE_FULL" {
            $childArgs = @(
                "-Modes"
            ) + $CowrieModes + @(
                "-Dataset", "$CowrieDataset",
                "-PythonExe", "$PythonExe",
                "-BinaryEpochs", "$BinaryEpochs",
                "-MulticlassEpochs", "$MulticlassEpochs",
                "-AnomalyEstimators", "$AnomalyEstimators",
                "-NFolds", "$CowrieNFolds",
                "-FeatureProfile", "$CowrieFeatureProfile"
            )
            if (-not $RunPreprocess) {
                $childArgs += "-SkipPreprocess"
            }
            $childArgs = Add-CommonSkips $childArgs
            Invoke-Step "COWRIE_FULL" "src\scripts\cowrie_full_run_all_models.ps1" $childArgs
        }
        "CSR-LANL" {
            $childArgs = @(
                "-Modes"
            ) + $CsrModes + @(
                "-Dataset", "$CsrDataset",
                "-DatasetsBase", "$CsrDatasetsBase",
                "-PythonExe", "$PythonExe",
                "-BinaryEpochs", "$BinaryEpochs",
                "-MulticlassEpochs", "$MulticlassEpochs",
                "-AnomalyEstimators", "$AnomalyEstimators"
            )
            if ($SkipDatasetCheck) {
                $childArgs += "-SkipDatasetCheck"
            }
            $childArgs = Add-CommonSkips $childArgs
            Invoke-Step "CSR-LANL" "src\scripts\csr_lanl_run_all_models.ps1" $childArgs
        }
    }
}

if ($Failures.Count -gt 0) {
    Write-Host "`nCompleted with failures:" -ForegroundColor Yellow
    $Failures | Format-Table -AutoSize
    exit 1
}

Write-Host "`nAll selected dataset model training finished." -ForegroundColor Green