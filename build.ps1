[CmdletBinding()]
param(
    [string]$ProjectPath,               # Optional: path to the package folder
    [switch]$SkipInstall,               # Skip dependency install
    [switch]$Clean,                     # Delete ./dist before building
    [switch]$NoCopyAssets,              # Don't copy *.png/*.svg into dist
    [switch]$Watch,                     # Build in watch mode (tsc -w)
    [switch]$Pack,                      # Run `npm pack` after build
    [switch]$OpenDist                   # Open dist/ in Explorer at the end
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Resolve-ProjectDir {
    param([string]$PreferredPath)

    # 1) If an explicit path is provided and valid
    if ($PreferredPath) {
        $p = Resolve-Path -Path $PreferredPath -ErrorAction SilentlyContinue
        if ($p -and (Test-Path (Join-Path $p "package.json"))) { return $p }
    }

    # 2) Use the current directory if it has a package.json
    if (Test-Path "package.json") {
        return (Resolve-Path ".")
    }

    # 3) Common monorepo layout: ./n8n-nodes-cloudmersive-virus-scan-api
    $candidate = Join-Path "." "n8n-nodes-cloudmersive-virus-scan-api"
    if (Test-Path (Join-Path $candidate "package.json")) {
        return (Resolve-Path $candidate)
    }

    # 4) Fallback: search for package.json with our package name
    $matches = Get-ChildItem -Path . -Filter "package.json" -Recurse -ErrorAction SilentlyContinue |
        Where-Object {
            try { ((Get-Content $_.FullName -Raw | ConvertFrom-Json).name) -eq "n8n-nodes-cloudmersive-virus-scan-api" } catch { $false }
        }

    if ($matches) {
        return (Resolve-Path $matches[0].DirectoryName)
    }

    throw "Could not locate project folder 'n8n-nodes-cloudmersive-virus-scan-api'. Use -ProjectPath to specify it."
}

function Copy-NodeAssets {
    # Copy *.svg and *.png from nodes/** to dist/nodes/** (preserve structure)
    Write-Host "==> Copying icon assets to dist/..." -ForegroundColor Cyan
    $root = (Resolve-Path ".").Path
    $assets = Get-ChildItem -Path "nodes" -Include *.svg,*.png -Recurse -ErrorAction SilentlyContinue
    foreach ($a in $assets) {
        $rel = $a.FullName.Substring($root.Length + 1)  # e.g. nodes\CloudmersiveVirusScanApi\cloudmersive.png
        $dest = Join-Path "dist" $rel
        $destDir = Split-Path -Parent $dest
        if (-not (Test-Path $destDir)) {
            New-Item -ItemType Directory -Force -Path $destDir | Out-Null
        }
        Copy-Item $a.FullName $dest -Force
        Write-Host "   - $rel" -ForegroundColor DarkGray
    }
}

$originalDir = Get-Location
try {
    $projectDir = Resolve-ProjectDir -PreferredPath $ProjectPath
    Set-Location $projectDir
    Write-Host "==> Building project at: $projectDir" -ForegroundColor Cyan

    # Optional clean
    if ($Clean -and (Test-Path "dist")) {
        Write-Host "==> Cleaning dist/" -ForegroundColor Cyan
        Remove-Item -Recurse -Force "dist"
    }

    # Node version check (warn if < 16)
    try {
        $nodeVerString = (node -v).Trim()
        $nodeVer = $nodeVerString.TrimStart('v')
        if ([version]$nodeVer -lt [version]'16.0.0') {
            Write-Warning "Detected Node $nodeVerString, but package engines require Node >= 16."
        }
    } catch {
        Write-Warning "Could not determine Node.js version."
    }

    # Install (unless skipped)
    if (-not $SkipInstall) {
        if (Test-Path "package-lock.json") {
            Write-Host "==> npm ci" -ForegroundColor Cyan
            npm ci
        } else {
            Write-Host "==> npm install" -ForegroundColor Cyan
            npm install
        }
    } else {
        Write-Host "==> Skipping install (-SkipInstall)" -ForegroundColor Yellow
    }

    # Build (watch or one-off)
    if ($Watch) {
        if (-not $NoCopyAssets) { Copy-NodeAssets }
        Write-Host "==> Starting TypeScript watch (Ctrl+C to stop) ..." -ForegroundColor Cyan
        # Use the package script and pass '-w' through
        $args = @("run", "build", "--", "-w")
        $proc = Start-Process -FilePath "npm" -ArgumentList $args -NoNewWindow -PassThru -Wait
        if ($proc.ExitCode -ne 0) { throw "Build watch exited with code $($proc.ExitCode)" }
    } else {
        Write-Host "==> npm run build" -ForegroundColor Cyan
        $proc = Start-Process -FilePath "npm" -ArgumentList @("run","build") -NoNewWindow -PassThru -Wait
        if ($proc.ExitCode -ne 0) { throw "Build failed with exit code $($proc.ExitCode)" }

        if (-not $NoCopyAssets) { Copy-NodeAssets }

        # Sanity check
        $compiledNode = "dist/nodes/CloudmersiveVirusScanApi/CloudmersiveVirusScanApi.node.js"
        if (-not (Test-Path $compiledNode)) {
            throw "Build output missing: $compiledNode"
        }

        if ($Pack) {
            Write-Host "==> npm pack" -ForegroundColor Cyan
            $packOutput = & npm pack 2>&1
            if ($LASTEXITCODE -ne 0) { throw "npm pack failed: $packOutput" }
            $tgz = ($packOutput | Select-Object -Last 1).ToString().Trim()
            if ($tgz -and (Test-Path $tgz)) {
                Write-Host "==> Package created: $tgz" -ForegroundColor Green
            } else {
                Write-Warning "npm pack did not produce a .tgz file in the current directory."
            }
        }

        if ($OpenDist) {
            Write-Host "==> Opening dist/" -ForegroundColor Cyan
            Invoke-Item "dist"
        }

        Write-Host "==> Build complete." -ForegroundColor Green
    }
}
finally {
    Set-Location $originalDir
}
