# ============================================================
#  PureCyber — Otomatik Kurulum Scripti
#  Npcap driver + SDK'yı indirir, kurar, build ortamını hazırlar
#  Çalıştır: powershell -ExecutionPolicy Bypass -File setup.ps1
# ============================================================

$ErrorActionPreference = "Stop"
$ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Path

function Write-Step($msg) {
    Write-Host "`n[*] $msg" -ForegroundColor Cyan
}
function Write-OK($msg) {
    Write-Host "  [+] $msg" -ForegroundColor Green
}
function Write-Warn($msg) {
    Write-Host "  [!] $msg" -ForegroundColor Yellow
}
function Write-Err($msg) {
    Write-Host "  [X] $msg" -ForegroundColor Red
}

# ASCII Banner
Write-Host @"

  ██████╗ ██╗   ██╗██████╗ ███████╗     ██████╗██╗   ██╗██████╗ ███████╗██████╗ 
  ██╔══██╗██║   ██║██╔══██╗██╔════╝    ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗
  ██████╔╝██║   ██║██████╔╝█████╗      ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝
  ██╔═══╝ ██║   ██║██╔══██╗██╔══╝      ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗
  ██║     ╚██████╔╝██║  ██║███████╗    ╚██████╗   ██║   ██████╔╝███████╗██║  ██║
  ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝     ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝

  [ Otomatik Kurulum ]
"@ -ForegroundColor Cyan

# ── Yönetici kontrolü ─────────────────────────────────────────────────────────
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $isAdmin) {
    Write-Err "Yönetici (Administrator) olarak çalıştırılmalı!"
    Write-Warn "Şu komutu kullan: Start-Process powershell -Verb RunAs -ArgumentList '-ExecutionPolicy Bypass -File setup.ps1'"
    exit 1
}
Write-OK "Yönetici hakları: OK"

# ── TLS 1.2 zorla (eski Windows için) ────────────────────────────────────────
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ── Npcap versiyonunu belirle ─────────────────────────────────────────────────
$NpcapVersion    = "1.79"
$NpcapSDKVersion = "1.13"
$NpcapInstallerUrl = "https://npcap.com/dist/npcap-$NpcapVersion.exe"
$NpcapSDKUrl       = "https://npcap.com/dist/npcap-sdk-$NpcapSDKVersion.zip"

$TempDir   = Join-Path $env:TEMP "purecyber_setup"
$SDKDir    = Join-Path $ProjectDir "npcap-sdk"

New-Item -ItemType Directory -Force -Path $TempDir | Out-Null

# ─────────────────────────────────────────────────────────────────────────────
# ADIM 1: Npcap Driver kurulu mu?
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Npcap driver kontrol ediliyor..."

$npcapService = Get-Service -Name "npcap" -ErrorAction SilentlyContinue
if ($npcapService) {
    Write-OK "Npcap zaten kurulu (servis: npcap)"
} else {
    Write-Warn "Npcap bulunamadı, indiriliyor..."

    $installerPath = Join-Path $TempDir "npcap-$NpcapVersion.exe"

    # İndir
    Write-Host "  Indiriliyor: $NpcapInstallerUrl" -ForegroundColor Gray
    try {
        $wc = New-Object System.Net.WebClient
        $wc.DownloadFile($NpcapInstallerUrl, $installerPath)
        Write-OK "İndirildi: npcap-$NpcapVersion.exe"
    } catch {
        Write-Err "İndirme hatası: $_"
        Write-Warn "Manuel indir: https://npcap.com/#download"
        exit 1
    }

    # Sessiz kurulum
    Write-Step "Npcap kuruluyor (sessiz mod)..."
    Write-Host "  Not: WinPcap uyumluluk modu açık olarak kurulacak" -ForegroundColor Gray

    $proc = Start-Process -FilePath $installerPath `
        -ArgumentList "/S", "/winpcap_mode=yes", "/loopback_support=yes", "/dot11_support=no" `
        -Wait -PassThru

    if ($proc.ExitCode -eq 0) {
        Write-OK "Npcap başarıyla kuruldu!"
    } elseif ($proc.ExitCode -eq 1) {
        # 1 = already installed / yeniden başlat gerekebilir
        Write-OK "Npcap kuruldu (yeniden başlatma gerekebilir)"
    } else {
        Write-Err "Npcap kurulum hatası. Exit code: $($proc.ExitCode)"
        Write-Warn "Manuel kur: https://npcap.com/#download"
        exit 1
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# ADIM 2: Npcap SDK
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Npcap SDK kontrol ediliyor..."

$pcapHeader = Join-Path $SDKDir "Include\pcap.h"
if (Test-Path $pcapHeader) {
    Write-OK "Npcap SDK zaten mevcut: $SDKDir"
} else {
    Write-Warn "SDK bulunamadı, indiriliyor..."

    $sdkZip  = Join-Path $TempDir "npcap-sdk-$NpcapSDKVersion.zip"

    Write-Host "  İndiriliyor: $NpcapSDKUrl" -ForegroundColor Gray
    try {
        $wc = New-Object System.Net.WebClient
        $wc.DownloadFile($NpcapSDKUrl, $sdkZip)
        Write-OK "İndirildi: npcap-sdk-$NpcapSDKVersion.zip"
    } catch {
        Write-Err "SDK indirme hatası: $_"
        Write-Warn "Manuel indir: https://npcap.com/#download (Npcap SDK)"
        exit 1
    }

    # Zip'i çıkart
    Write-Step "SDK çıkartılıyor..."
    $extractTemp = Join-Path $TempDir "npcap_sdk_extracted"
    New-Item -ItemType Directory -Force -Path $extractTemp | Out-Null
    Expand-Archive -Path $sdkZip -DestinationPath $extractTemp -Force

    # Klasör yapısını düzenle (zip içinde npcap-sdk-x.y/ olabilir)
    $innerDir = Get-ChildItem $extractTemp -Directory | Select-Object -First 1
    if ($innerDir) {
        if (Test-Path $SDKDir) { Remove-Item $SDKDir -Recurse -Force }
        Move-Item $innerDir.FullName $SDKDir
    } else {
        # Direkt içeriği taşı
        if (Test-Path $SDKDir) { Remove-Item $SDKDir -Recurse -Force }
        Move-Item $extractTemp $SDKDir
    }

    if (Test-Path $pcapHeader) {
        Write-OK "SDK hazır: $SDKDir"
    } else {
        Write-Err "SDK çıkartma başarısız. pcap.h bulunamadı."
        Write-Warn "Manuel kur: https://npcap.com/#download (SDK zip'ini npcap-sdk/ klasörüne çıkart)"
        exit 1
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# ADIM 3: Visual Studio / CMake kontrolü
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Build araçları kontrol ediliyor..."

# CMake kontrolü
$cmake = Get-Command cmake -ErrorAction SilentlyContinue
if ($cmake) {
    Write-OK "CMake bulundu: $($cmake.Source)"
} else {
    Write-Warn "CMake bulunamadı!"
    Write-Host "  İndir: https://cmake.org/download/" -ForegroundColor Gray
    Write-Host "  Veya: winget install Kitware.CMake" -ForegroundColor Gray
}

# VS Build Tools kontrolü (cl.exe)
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (Test-Path $vswhere) {
    $vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
    if ($vsPath) {
        Write-OK "Visual Studio bulundu: $vsPath"
    } else {
        Write-Warn "Visual Studio C++ araçları bulunamadı"
        Write-Host "  İndir: https://visualstudio.microsoft.com/downloads/" -ForegroundColor Gray
        Write-Host "  'Desktop development with C++' workload'ını seç" -ForegroundColor Gray
    }
} else {
    Write-Warn "Visual Studio Installer bulunamadı"
    Write-Host "  İndir: https://visualstudio.microsoft.com/downloads/" -ForegroundColor Gray
}

# ─────────────────────────────────────────────────────────────────────────────
# ADIM 4: Otomatik Build
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Proje build ediliyor..."

if (-not $cmake) {
    Write-Warn "CMake yok, build atlanıyor. CMake kur, sonra tekrar çalıştır."
} else {
    $BuildDir = Join-Path $ProjectDir "build"
    New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null

    Push-Location $BuildDir
    try {
        Write-Host "  cmake .. -A x64 ..." -ForegroundColor Gray
        $configResult = & cmake .. -A x64 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Err "CMake configure hatası:"
            Write-Host $configResult -ForegroundColor Red
        } else {
            Write-OK "Configure OK"
            Write-Host "  cmake --build . --config Release ..." -ForegroundColor Gray
            $buildResult = & cmake --build . --config Release 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Err "Build hatası:"
                Write-Host $buildResult -ForegroundColor Red
            } else {
                Write-OK "Build başarılı!"
                $exePath = Join-Path $BuildDir "Release\purecyber.exe"
                if (Test-Path $exePath) {
                    Write-OK "Çalıştırılabilir: $exePath"
                }
            }
        }
    } finally {
        Pop-Location
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# ADIM 5: Temizlik
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Geçici dosyalar temizleniyor..."
Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue
Write-OK "Temizlendi"

# ─────────────────────────────────────────────────────────────────────────────
# ÖZET
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "`n"
Write-Host "  ─────────────────────────────────────────────" -ForegroundColor Cyan
Write-Host "  KURULUM TAMAMLANDI!" -ForegroundColor Green
Write-Host "  ─────────────────────────────────────────────" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Kullanım (Administrator olarak):" -ForegroundColor White
Write-Host "    .\build\Release\purecyber.exe --list" -ForegroundColor Yellow
Write-Host "    .\build\Release\purecyber.exe" -ForegroundColor Yellow
Write-Host "    .\build\Release\purecyber.exe --webhook https://discord.com/api/webhooks/..." -ForegroundColor Yellow
Write-Host ""
