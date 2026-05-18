param(
    [string[]]$Modes = @("date"),
    [string]$PythonExe = "python",
    [string]$WindowSize = "1min",
    [int]$BinaryEpochs = 215,
    [int]$MulticlassEpochs = 215,
    [int]$AnomalyEstimators = 315,
    [int]$MinMulticlassWindows = 30,
    [int]$FailedLoginThreshold = 3,
    [int]$AnomalyNJobs = 1,
    [double]$SampleFrac,
    [switch]$SkipPreprocess,
    [switch]$SkipBinaryHgb,
    [switch]$SkipMulticlass,
    [switch]$SkipAnomaly,
    [switch]$SkipCompare,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$runner = Join-Path $scriptDir "cowrie_full_run_all_models.ps1"
if (!(Test-Path $runner)) {
    throw "No existe el runner de COWRIE_FULL: $runner"
}

$settings = @{
    Modes = $Modes
    Dataset = "COWRIE_FULL"
    PythonExe = $PythonExe
    WindowSize = $WindowSize
    BinaryEpochs = $BinaryEpochs
    MulticlassEpochs = $MulticlassEpochs
    AnomalyEstimators = $AnomalyEstimators
    MinMulticlassWindows = $MinMulticlassWindows
    FailedLoginThreshold = $FailedLoginThreshold
    AnomalyNJobs = $AnomalyNJobs
}

if ($PSBoundParameters.ContainsKey("SampleFrac")) {
    $settings.SampleFrac = $SampleFrac
}
if ($SkipPreprocess) {
    $settings.SkipPreprocess = $true
}
if ($SkipBinaryHgb) {
    $settings.SkipBinaryHgb = $true
}
if ($SkipMulticlass) {
    $settings.SkipMulticlass = $true
}
if ($SkipAnomaly) {
    $settings.SkipAnomaly = $true
}
if ($SkipCompare) {
    $settings.SkipCompare = $true
}
if ($DryRun) {
    $settings.DryRun = $true
}

& $runner @settings
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
