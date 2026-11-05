# Sets up WithHuman for Claude Code in the current folder (Windows), replacing any earlier
# WithHuman setup. Run it in PowerShell, in the folder you start Claude Code in:
#
#   $env:WITHHUMAN_SERVER = "https://withhuman.example.com"
#   irm https://raw.githubusercontent.com/BobWithHuman/withhuman-core/main/deploy/client/setup-project.ps1 | iex
#
# $env:WITHHUMAN_SERVER is the address of your own engine; WithHuman is self-hosted, so there is no
# default. A team name goes in $env:WITHHUMAN_TEAM first; $env:WITHHUMAN_REF picks the branch the
# files are fetched from (default: main). See configure.py for what it changes. WITHHUMAN_CLIENT_ID
# is set for new windows and for this one.
& {
    $ErrorActionPreference = "Stop"
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $ref = if ($env:WITHHUMAN_REF) { $env:WITHHUMAN_REF } else { "main" }
    $team = if ($env:WITHHUMAN_TEAM) { $env:WITHHUMAN_TEAM } else { "default" }
    $base = "https://raw.githubusercontent.com/BobWithHuman/withhuman-core/$ref/deploy/client"

    if (-not $env:WITHHUMAN_SERVER) {
        throw @"
WITHHUMAN_SERVER is required: the address of your own WithHuman engine.
  local Compose host:  http://127.0.0.1:3000
  EC2 single node:     https://<the single-node domain_name>
  EKS deployment:      https://<the Ingress host>
"@
    }

    # Python 3.8 or later: the py launcher first, then python and python3 on PATH. The Microsoft
    # Store's stand-in python.exe prints nothing and fails, so it is passed over.
    $python = $null
    foreach ($candidate in @(@{ Name = "py"; Args = @("-3") }, @{ Name = "python"; Args = @() }, @{ Name = "python3"; Args = @() })) {
        if (-not (Get-Command $candidate.Name -ErrorAction SilentlyContinue)) { continue }
        try {
            $found = & $candidate.Name @($candidate.Args) -c "import sys; print(sys.executable if sys.version_info >= (3, 8) else '')" 2>$null
        } catch {
            continue
        }
        if ($LASTEXITCODE -eq 0 -and $found) {
            $python = ($found | Select-Object -Last 1).Trim()
            if ($python) { break }
        }
    }
    if (-not $python) {
        throw "WithHuman needs Python 3.8 or later: https://www.python.org/downloads/ (tick 'Add python.exe to PATH')"
    }

    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("withhuman-" + [guid]::NewGuid())
    New-Item -ItemType Directory -Force -Path (Join-Path $tmp "hooks") | Out-Null
    try {
        Invoke-WebRequest -UseBasicParsing -Uri "$base/configure.py" -OutFile (Join-Path $tmp "configure.py")
        Invoke-WebRequest -UseBasicParsing -Uri "$base/hooks/pre-tool-use.py" -OutFile (Join-Path $tmp "hooks\pre-tool-use.py")
        & $python (Join-Path $tmp "configure.py") --project (Get-Location).Path --team $team --server $env:WITHHUMAN_SERVER
        if ($LASTEXITCODE -ne 0) { throw "WithHuman setup failed" }
    } finally {
        Remove-Item -Recurse -Force -Path $tmp -ErrorAction SilentlyContinue
    }
}
# configure.py set it for new windows; this window gets it too.
$env:WITHHUMAN_CLIENT_ID = [Environment]::GetEnvironmentVariable("WITHHUMAN_CLIENT_ID", "User")
