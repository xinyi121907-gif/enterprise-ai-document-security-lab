param([switch]$CheckOnly, [string]$PythonPath = "")
$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot
$customPython = [bool]$PythonPath
if (!$PythonPath) { $PythonPath = Join-Path $PSScriptRoot '.venv/Scripts/python.exe' }
$pythonPath = [System.IO.Path]::GetFullPath($PythonPath)
if (!(Test-Path -LiteralPath $pythonPath)) {
    if ($customPython) { throw 'The specified Python executable does not exist.' }
    py -3.11 -m venv .venv
    if ($LASTEXITCODE -ne 0) { throw 'Python 3.11 is required.' }
}
& $pythonPath -c "import streamlit, ollama, pydantic, yaml"
if ($LASTEXITCODE -ne 0) {
    & $pythonPath -m pip install -r requirements.txt
    if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed; check network and retry.' }
}
try { $models = Invoke-RestMethod 'http://localhost:11434/api/tags' -TimeoutSec 10 }
catch { throw 'Ollama is unavailable. Start Ollama and retry.' }
if (!($models.models.name -contains 'qwen2.5:7b')) { throw 'Run: ollama pull qwen2.5:7b, then retry.' }
if ($CheckOnly) { Write-Output 'Startup checks passed'; exit 0 }
& $pythonPath -m streamlit run app.py
exit $LASTEXITCODE
