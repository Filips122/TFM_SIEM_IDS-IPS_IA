param(
    [string]$PythonExe = "python",

    [string[]]$NuswModes = @("random", "groupkfold", "official"),
    [string[]]$UgrModes = @("date"),
    [string[]]$LabModes = @("date"),
    [string[]]$CowrieModes = @("date"),
    [string[]]$CsrModes = @("date", "groupkfold"),

    [string]$UgrDataset = "UGR16_MARAPR_HYBRID",
    [string]$LabDataset = "LAB-ALERTS",
    [string]$CowrieDataset = "COWRIE_FULL",
    [string]$CsrDataset = "CSR-LANL",
    [string]$CsrDatasetsBase = "src/models/CSR-LANL/datasets_redteam",

    [ValidateSet("auth", "auth_flow", "auth_flow_dns", "all")]
    [string]$CsrSourceSet = "auth_flow",

    [int]$CicEpochs = 20,
    [int]$BinaryEpochs = 215,
    [int]$MulticlassEpochs = 215,
    [int]$AnomalyEstimators = 315,
    [int]$MlpEpochs = 40,

    [int]$NuswNFolds = 8,
    [int]$UgrNFolds = 8,
    [int]$LabNFolds = 5,
    [int]$CowrieNFolds = 5,
    [int]$CsrNFolds = 5,
    [int[]]$GroupFolds = @(0),

    [double]$CsrRedteamWindowHours = 1.0,
    [int]$CsrRedteamWindowLimit = 0,
    [int]$CsrRedteamExclusionWindows = 2,
    [int]$CsrMinRedteamMatches = 1,
    [int]$CsrWindowSeconds = 60,
    [int]$CsrChunkSize = 250000,
    [int]$CsrMaxRowsPerSource = 0,

    [int]$UgrAnomalyMaxTrainRows = 500000,
    [int]$UgrAnomalyMaxEvalRows = 200000,
    [int]$UgrAnomalyNJobs = 1,

    [double]$SampleFrac,

    [switch]$Light,
    [switch]$AllGroupFolds,
    [switch]$SkipCic,
    [switch]$SkipNusw,
    [switch]$SkipUgr,
    [switch]$SkipLab,
    [switch]$SkipCowrie,
    [switch]$SkipCsr,
    [switch]$SkipReusablePreprocess,
    [switch]$SkipCsrPrepare,
    [switch]$SkipValidation,
    [switch]$SkipDatasetCheck,
    [switch]$SkipBinaryHgb,
    [switch]$SkipMulticlass,
    [switch]$SkipAnomaly,
    [switch]$SkipMlp,
    [switch]$SkipCompare,
    [switch]$CsrNoProgress,
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
$Failures = @()

if ($Light) {
    Write-Host "Light mode enabled: using smoke-test epochs, samples, and bounded CSR/UGR settings." -ForegroundColor Yellow

    if (-not $PSBoundParameters.ContainsKey("CicEpochs")) { $CicEpochs = 2 }
    if (-not $PSBoundParameters.ContainsKey("BinaryEpochs")) { $BinaryEpochs = 3 }
    if (-not $PSBoundParameters.ContainsKey("MulticlassEpochs")) { $MulticlassEpochs = 3 }
    if (-not $PSBoundParameters.ContainsKey("AnomalyEstimators")) { $AnomalyEstimators = 15 }
    if (-not $PSBoundParameters.ContainsKey("MlpEpochs")) { $MlpEpochs = 2 }

    if (-not $PSBoundParameters.ContainsKey("SampleFrac")) {
        $SampleFrac = 0.20
        $hasSampleFrac = $true
    }

    if (-not $PSBoundParameters.ContainsKey("NuswModes")) { $NuswModes = @("random", "official") }
    if (-not $PSBoundParameters.ContainsKey("UgrModes")) { $UgrModes = @("date") }
    if (-not $PSBoundParameters.ContainsKey("LabModes")) { $LabModes = @("date") }
    if (-not $PSBoundParameters.ContainsKey("CowrieModes")) { $CowrieModes = @("date") }
    if (-not $PSBoundParameters.ContainsKey("CsrModes")) { $CsrModes = @("random") }
    if (-not $PSBoundParameters.ContainsKey("CsrSourceSet")) { $CsrSourceSet = "auth" }

    if (-not $PSBoundParameters.ContainsKey("CsrRedteamWindowLimit")) { $CsrRedteamWindowLimit = 5 }
    if (-not $PSBoundParameters.ContainsKey("CsrRedteamWindowHours")) { $CsrRedteamWindowHours = 0.5 }
    if (-not $PSBoundParameters.ContainsKey("CsrChunkSize")) { $CsrChunkSize = 100000 }
    if (-not $PSBoundParameters.ContainsKey("CsrNoProgress")) { $CsrNoProgress = $true }

    if (-not $PSBoundParameters.ContainsKey("UgrAnomalyMaxTrainRows")) { $UgrAnomalyMaxTrainRows = 50000 }
    if (-not $PSBoundParameters.ContainsKey("UgrAnomalyMaxEvalRows")) { $UgrAnomalyMaxEvalRows = 20000 }
    if (-not $PSBoundParameters.ContainsKey("UgrAnomalyNJobs")) { $UgrAnomalyNJobs = 1 }
}

function Quote-PowerShellValue([string]$value) {
    return "'" + ($value -replace "'", "''") + "'"
}

function Build-ChildCommand([string]$scriptPath, [string[]]$scriptArgs) {
    $arrayParams = @(
        "-Datasets",
        "-Modes",
        "-NuswModes",
        "-UgrModes",
        "-LabModes",
        "-CowrieModes",
        "-CsrModes",
        "-GroupFolds"
    )
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

    $childCommand = Build-ChildCommand $fullPath $scriptArgs
    & $powerShellExe -NoProfile -ExecutionPolicy Bypass -Command $childCommand
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

function Add-CommonModelArgs([string[]]$ArgList, [switch]$SupportsMlp) {
    if ($SkipBinaryHgb) { $ArgList += "-SkipBinaryHgb" }
    if ($SkipMulticlass) { $ArgList += "-SkipMulticlass" }
    if ($SkipAnomaly) { $ArgList += "-SkipAnomaly" }
    if ($SkipMlp -and $SupportsMlp) { $ArgList += "-SkipBinaryMlp" }
    if ($SkipCompare) { $ArgList += "-SkipCompare" }
    if ($hasSampleFrac) { $ArgList += @("-SampleFrac", "$SampleFrac") }
    return $ArgList
}

function GroupFoldArgs() {
    if ($AllGroupFolds) {
        return @("-AllGroupFolds")
    }
    return @("-GroupFolds") + @($GroupFolds | ForEach-Object { "$($_)" })
}

Write-Host "=== Refactored all-dataset model training ===" -ForegroundColor Green
Write-Host "Repo root : $repoRoot"
Write-Host "Python    : $PythonExe"
Write-Host "Shell     : $powerShellExe"
Write-Host "Dry run   : $DryRun"
Write-Host "Light     : $Light"
Write-Host "CSR data  : $CsrDatasetsBase ($CsrSourceSet, redteam limit=$CsrRedteamWindowLimit)"

if (-not $SkipNusw) {
    $nuswArgs = @(
        "-Modes"
    ) + $NuswModes + @(
        "-PythonExe", "$PythonExe",
        "-SourceSet", "raw4",
        "-AnomalyGroupTrainPolicy", "fallback_official_benign",
        "-BinaryEpochs", "$BinaryEpochs",
        "-MulticlassEpochs", "$MulticlassEpochs",
        "-AnomalyEstimators", "$AnomalyEstimators",
        "-MlpEpochs", "$MlpEpochs",
        "-NFolds", "$NuswNFolds",
        "-SkipPreprocess"
    ) + (GroupFoldArgs)

    if ($SkipValidation) { $nuswArgs += "-SkipValidation" }
    $nuswArgs = Add-CommonModelArgs $nuswArgs -SupportsMlp
    Invoke-Step "UNSW-NB15 refactored" "src\scripts\nusw_run_all_models.ps1" $nuswArgs
}

$coreDatasets = @()
if (-not $SkipCic) { $coreDatasets += "CIC-IDS2017" }
if (-not $SkipUgr) { $coreDatasets += "UGR16" }
if (-not $SkipLab) { $coreDatasets += "LAB-ALERTS" }
if (-not $SkipCowrie) { $coreDatasets += "COWRIE_FULL" }

if ($coreDatasets.Count -gt 0) {
    $coreArgs = @(
        "-Datasets"
    ) + $coreDatasets + @(
        "-PythonExe", "$PythonExe",
        "-UgrModes"
    ) + $UgrModes + @(
        "-LabModes"
    ) + $LabModes + @(
        "-CowrieModes"
    ) + $CowrieModes + @(
        "-UgrDataset", "$UgrDataset",
        "-LabDataset", "$LabDataset",
        "-CowrieDataset", "$CowrieDataset",
        "-CicEpochs", "$CicEpochs",
        "-BinaryEpochs", "$BinaryEpochs",
        "-MulticlassEpochs", "$MulticlassEpochs",
        "-AnomalyEstimators", "$AnomalyEstimators",
        "-MlpEpochs", "$MlpEpochs",
        "-UgrNFolds", "$UgrNFolds",
        "-LabNFolds", "$LabNFolds",
        "-CowrieNFolds", "$CowrieNFolds",
        "-UgrAnomalyMaxTrainRows", "$UgrAnomalyMaxTrainRows",
        "-UgrAnomalyMaxEvalRows", "$UgrAnomalyMaxEvalRows",
        "-UgrAnomalyNJobs", "$UgrAnomalyNJobs"
    ) + (GroupFoldArgs)

    if ($SkipValidation) { $coreArgs += "-SkipValidation" }
    if ($SkipDatasetCheck) { $coreArgs += "-SkipDatasetCheck" }
    if ($ContinueOnError) { $coreArgs += "-ContinueOnError" }
    $coreArgs = Add-CommonModelArgs $coreArgs -SupportsMlp
    Invoke-Step "CIC/UGR/LAB/COWRIE" "src\scripts\run_all_models.ps1" $coreArgs
}

if (-not $SkipCsr) {
    $csrArgs = @(
        "-Modes"
    ) + $CsrModes + @(
        "-Dataset", "$CsrDataset",
        "-DatasetsBase", "$CsrDatasetsBase",
        "-SourceSet", "$CsrSourceSet",
        "-PythonExe", "$PythonExe",
        "-WindowSeconds", "$CsrWindowSeconds",
        "-RedteamWindowHours", "$CsrRedteamWindowHours",
        "-RedteamWindowLimit", "$CsrRedteamWindowLimit",
        "-RedteamExclusionWindows", "$CsrRedteamExclusionWindows",
        "-MinRedteamMatches", "$CsrMinRedteamMatches",
        "-ChunkSize", "$CsrChunkSize",
        "-MaxRowsPerSource", "$CsrMaxRowsPerSource",
        "-NFolds", "$CsrNFolds",
        "-BinaryEpochs", "$BinaryEpochs",
        "-MulticlassEpochs", "$MulticlassEpochs",
        "-AnomalyEstimators", "$AnomalyEstimators"
    ) + (GroupFoldArgs)

    $csrArgs += "-SkipPrepare"
    if ($SkipValidation) { $csrArgs += "-SkipValidation" }
    if ($SkipBinaryHgb) { $csrArgs += "-SkipBinaryHgb" }
    if ($SkipMulticlass) { $csrArgs += "-SkipMulticlass" }
    if ($SkipAnomaly) { $csrArgs += "-SkipAnomaly" }
    if ($SkipCompare) { $csrArgs += "-SkipCompare" }
    if ($CsrNoProgress) { $csrArgs += "-NoProgress" }
    Invoke-Step "CSR-LANL redteam refactored" "src\scripts\csr_lanl_run_redteam_models.ps1" $csrArgs
}

if ($Failures.Count -gt 0) {
    Write-Host "`nCompleted with failures:" -ForegroundColor Yellow
    $Failures | Format-Table -AutoSize
    exit 1
}

Write-Host "`nRefactored all-dataset model training finished." -ForegroundColor Green