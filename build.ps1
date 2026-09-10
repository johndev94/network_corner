$ErrorActionPreference = 'Stop'

$projectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$compiler = "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
$output = Join-Path $projectDir 'NetworkCorner.exe'

if (-not (Test-Path -LiteralPath $compiler)) {
    throw "Built-in C# compiler not found at $compiler"
}

& $compiler /nologo /target:winexe /optimize+ /platform:anycpu /win32manifest:"$projectDir\app.manifest" /out:"$output" /reference:System.dll /reference:System.Core.dll /reference:System.Drawing.dll /reference:System.Windows.Forms.dll /reference:System.Web.Extensions.dll "$projectDir\Program.cs"
if ($LASTEXITCODE -ne 0) { throw 'Compilation failed.' }

& $output --self-test
if ($LASTEXITCODE -ne 0) { throw 'Self-tests failed.' }

Write-Host "Built successfully: $output"
