# Sets up WithHuman for Claude Code, Codex CLI, Cursor CLI, GitHub Copilot CLI or Antigravity
# CLI in the current folder (Windows), replacing any
# earlier WithHuman setup. Run it in PowerShell, in the folder you start the agent in:
#
#   $env:WITHHUMAN_SERVER = "https://withhuman.example.com"
#   irm https://raw.githubusercontent.com/BobWithHuman/withhuman-core/main/deploy/client/setup-project.ps1 | iex
#
# $env:WITHHUMAN_SERVER is the address of your own engine; WithHuman is self-hosted, so there is no
# default. A team name goes in $env:WITHHUMAN_TEAM first; $env:WITHHUMAN_REF picks the branch the
# files are fetched from (default: main), $env:WITHHUMAN_BASE_URL another place serving the
# deploy/client folder (a mirror or a test). $env:WITHHUMAN_AGENT picks the agent: claude
# (default), antigravity, codex, copilot, cursor, hermes or openclaw (Hermes is set up for its
# profile, HERMES_HOME, not for the
# folder). Running it again updates the setup; $env:WITHHUMAN_UNINSTALL = "1" takes WithHuman out
# of the folder instead, keeping other hooks. See configure.py for what it changes.
# $env:WITHHUMAN_KEY is the user's key from the security team, when the engine issues keys.
# WITHHUMAN_CLIENT_ID (and WITHHUMAN_KEY) are set for new windows and for this one.
& {
    $ErrorActionPreference = "Stop"
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $ref = if ($env:WITHHUMAN_REF) { $env:WITHHUMAN_REF } else { "main" }
    $team = if ($env:WITHHUMAN_TEAM) { $env:WITHHUMAN_TEAM } else { "default" }
    $base = if ($env:WITHHUMAN_BASE_URL) { $env:WITHHUMAN_BASE_URL.TrimEnd("/") } else { "https://raw.githubusercontent.com/BobWithHuman/withhuman-core/$ref/deploy/client" }
    $agent = if ($env:WITHHUMAN_AGENT) { $env:WITHHUMAN_AGENT } else { "claude" }
    $uninstall = [bool]$env:WITHHUMAN_UNINSTALL
    # The files configure.py needs. Claude Code takes only its own hook; every other agent also
    # takes the shared bridge, that same hook (its bridge uses it to attach the program files a
    # command would run) and its own, named here. Adding an agent is one entry here and one in
    # configure.py's AGENTS.
    $bridges = @{
        antigravity = @("antigravity/withhuman-hook.py", "antigravity/antigravity_transcript.py")
        codex = @("codex/withhuman-hook.py", "codex/codex_transcript.py")
        copilot = @("copilot/withhuman-hook.py", "copilot/copilot_transcript.py")
        cursor = @("cursor/withhuman-hook.py")
        hermes = @("hermes/__init__.py", "hermes/plugin.yaml", "hermes/withhuman-hook.py")
        # OpenClaw loads a plugin recorded in its own configuration, so its own files are
        # that plugin and what OpenClaw needs to install it.
        openclaw = @("openclaw/withhuman-hook.py", "openclaw/index.js",
                     "openclaw/openclaw.plugin.json", "openclaw/package.json")
    }
    $files = @("configure.py", "hooks/pre-tool-use.py")
    if ($agent -ne "claude") {
        if (-not $bridges.ContainsKey($agent)) {
            throw "WITHHUMAN_AGENT must be claude or one of: $($bridges.Keys -join ', '): $agent"
        }
        $files += @("hooks/withhuman_bridge.py") + $bridges[$agent]
    }

    if (-not $env:WITHHUMAN_SERVER -and -not $uninstall) {
        throw @"
WITHHUMAN_SERVER is required: the address of your own WithHuman engine.
  personal Docker host:  http://127.0.0.1:3000
  EKS deployment:        https://<the Ingress host>
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
    try {
        foreach ($file in $files) {
            $target = Join-Path $tmp ($file -replace "/", "\")
            New-Item -ItemType Directory -Force -Path (Split-Path $target) | Out-Null
            Invoke-WebRequest -UseBasicParsing -Uri "$base/$file" -OutFile $target
        }
        $configure = Join-Path $tmp "configure.py"
        $project = (Get-Location).Path
        if ($uninstall) {
            & $python $configure --uninstall --agent $agent --project $project
        } elseif ($agent -ne "claude") {
            & $python $configure --agent $agent --project $project --team $team --server $env:WITHHUMAN_SERVER
        } else {
            & $python $configure --project $project --team $team --server $env:WITHHUMAN_SERVER
        }
        if ($LASTEXITCODE -ne 0) { throw "WithHuman setup failed" }
    } finally {
        Remove-Item -Recurse -Force -Path $tmp -ErrorAction SilentlyContinue
    }
}
# configure.py set it for new windows; this window gets it too.
$env:WITHHUMAN_CLIENT_ID = [Environment]::GetEnvironmentVariable("WITHHUMAN_CLIENT_ID", "User")
$key = [Environment]::GetEnvironmentVariable("WITHHUMAN_KEY", "User")
if ($key) { $env:WITHHUMAN_KEY = $key }
