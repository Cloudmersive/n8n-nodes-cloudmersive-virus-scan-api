[CmdletBinding()]
param(
    [string]$ProjectPath,               # Optional: path to the package folder
    [switch]$DryRun,                    # Use --dry-run
    [string]$Tag = "latest",            # npm dist-tag
    [string]$Otp,                       # 2FA one-time password
    [string]$Registry = "https://registry.npmjs.org/",
    [switch]$SkipBuild,                 # Skip `npm run build`
    [switch]$NoCopyAssets,              # Skip copying *.svg/*.png to dist
    [switch]$NoGitCheck                 # Skip git dirty-tree check
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Resolve-ProjectDir {
    param([string]$PreferredPath)

    # 1) If preferred path provided and valid, use it
    if ($PreferredPath) {
        $p = Resolve-Path -Path $PreferredPath -ErrorAction SilentlyContinue
        if ($p) {
            if (Test-Path (Join-Path $p "package.json")) { return $p }
        }
    }

    # 2) If current directory is the package
    if (Test-Path "package.json") {
        try {
            $pkg = Get-Content "package.json" -Raw | ConvertFrom-Json
            if ($pkg.name -eq "n8n-nodes-cloudmersive-virus-scan-api") {
                return (Resolve-Path ".")
            }
        } catch {}
    }

    # 3) Common monorepo layout: ./n8n-nodes-cloudmersive-virus-scan-api
    $candidate = Join-Path "." "n8n-nodes-cloudmersive-virus-scan-api"
    if (Test-Path (Join-Path $candidate "package.json")) {
        return (Resolve-Path $candidate)
    }

    # 4) Fallback: search for the package.json whose name matches
    $matches = Get-ChildItem -Path . -Filter "package.json" -Recurse -ErrorAction SilentlyContinue |
        Where-Object {
            try { ((Get-Content $_.FullName -Raw | ConvertFrom-Json).name) -eq "n8n-nodes-cloudmersive-virus-scan-api" } catch { $false }
        }

    if ($matches) {
        return (Resolve-Path $matches[0].DirectoryName)
    }

    throw "Could not locate project folder 'n8n-nodes-cloudmersive-virus-scan-api'. Use -ProjectPath to specify it."
}

$originalDir = Get-Location
try {
    $projectDir = Resolve-ProjectDir -PreferredPath $ProjectPath
    Set-Location $projectDir

    Write-Host "==> Project: $projectDir" -ForegroundColor Cyan

    # Optional: warn if working tree is dirty
    if (-not $NoGitCheck -and (Get-Command git -ErrorAction SilentlyContinue)) {
        $gitStatus = git status --porcelain
        if ($gitStatus) {
            Write-Warning "Working tree has uncommitted changes:"
            Write-Output $gitStatus
            Write-Warning "Consider committing or use -NoGitCheck to ignore."
        }
    }

    # Use NPM_TOKEN if provided (handy for CI)
    if ($env:NPM_TOKEN) {
        Write-Host "==> Using NPM_TOKEN from environment" -ForegroundColor Yellow
        npm config set "//registry.npmjs.org/:_authToken" "$env:NPM_TOKEN" | Out-Null
    }

    # Install deps
    if (Test-Path "package-lock.json") {
        Write-Host "==> npm ci" -ForegroundColor Cyan
        npm ci
    } else {
        Write-Host "==> npm install" -ForegroundColor Cyan
        npm install
    }

    # Build (unless skipped)
    if (-not $SkipBuild) {
        Write-Host "==> npm run build" -ForegroundColor Cyan
        npm run build
    } else {
        Write-Host "==> Skipping build (-SkipBuild)" -ForegroundColor Yellow
    }

    # Copy icons (*.svg, *.png) from nodes/** into dist/nodes/** so they ship with the package
    if (-not $NoCopyAssets) {
        Write-Host "==> Copying icon assets to dist/..." -ForegroundColor Cyan
        $root = (Resolve-Path ".").Path
        $assets = Get-ChildItem -Path "nodes" -Include *.svg,*.png -Recurse -ErrorAction SilentlyContinue
        foreach ($a in $assets) {
            $rel = $a.FullName.Substring($root.Length + 1) # e.g. nodes\CloudmersiveVirusScanApi\cloudmersive.png
            $dest = Join-Path "dist" $rel
            $destDir = Split-Path -Parent $dest
            if (-not (Test-Path $destDir)) {
                New-Item -ItemType Directory -Force -Path $destDir | Out-Null
            }
            Copy-Item $a.FullName $dest -Force
            Write-Host "   - $rel" -ForegroundColor DarkGray
        }
    } else {
        Write-Host "==> Skipping asset copy (-NoCopyAssets)" -ForegroundColor Yellow
    }

    # Verify compiled node exists
    $compiledNode = "dist/nodes/CloudmersiveVirusScanApi/CloudmersiveVirusScanApi.node.js"
    if (-not (Test-Path $compiledNode)) {
        throw "Build output missing: $compiledNode"
    }

    # Assemble npm publish args
    $publishArgs = @("publish", "--access", "public", "--tag", $Tag, "--registry", $Registry)
    if ($DryRun) { $publishArgs += "--dry-run" }
    if ($Otp)    { $publishArgs += @("--otp", $Otp) }

    Write-Host "==> npm $($publishArgs -join ' ')" -ForegroundColor Cyan
    $proc = Start-Process -FilePath "npm" -ArgumentList $publishArgs -NoNewWindow -PassThru -Wait
    if ($proc.ExitCode -ne 0) {
        throw "npm publish failed with exit code $($proc.ExitCode)"
    }

    Write-Host "==> Publish complete." -ForegroundColor Green
}
finally {
    Set-Location $originalDir
}
