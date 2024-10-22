# SourceClear CI Script for Windows

# Maybe turn on debug printing
if (-not ([string]::IsNullOrWhiteSpace($Env:DEBUG))) {
    $DebugPreference = 'Continue'
}

$DownloadUrl = 'https://download.sourceclear.com'
$CacheDirParent = Join-Path $Env:USERPROFILE ".veracode_wrapper"

function Get-Downloader {
    return New-Object System.Net.WebClient
}

function Download-String {
    param (
        [string]$url
    )
    Write-Debug "Downloading string from $url"
    $downloader = Get-Downloader

    return $downloader.DownloadString($url)
}

function Get-Version {
    $version = $Env:SRCCLR_VERSION
    if (-not (Test-Path Env:SRCCLR_VERSION)) {
        $version = Download-String("$DownloadUrl/LATEST_VERSION")
        $version = $version.Trim()
    }
    return $version
}

$SrcclrVersion = Get-Version

function Get-CacheDir {
    param (
        [string]$root,
        [string]$version
    )

    # This will not fail even if the directory already exists, hence
    # resilient to race condition.
    [void][System.IO.Directory]::CreateDirectory($root)

    # To prevent race condition, we move the installation into a
    # subdirectory whose name is the current Powershell process
    # id. Specifically, first we test if a directory where the
    # installation has completed can be found. If this was the case,
    # we use that subdirectory. Otherwise, we create a new
    # subdirectory using the Powershell process id as the name.
    $existing = Get-ChildItem $root | ? { Test-Path (Join-Path $_.FullName "srcclr-$version" | Join-Path -ChildPath "completed") } | select -first 1
    if ($null -eq $existing) {
        $cacheDir = Join-Path $root $PID

        if ([System.IO.Directory]::Exists($cacheDir)) {
            Remove-Item -path $cacheDir -recurse -force
        }

        [void][System.IO.Directory]::CreateDirectory($cacheDir)
        return $cacheDir
    }
    return $existing.FullName
}

$CacheDir = Get-CacheDir $CacheDirParent $SrcclrVersion


function Download-File {
    param (
        [string]$url,
        [string]$file
    )
    try {
        $uri = New-Object "System.Uri" "$url"
        $request = [System.Net.HttpWebRequest]::Create($uri)
        $request.set_Timeout(15000) #15 second timeout
        $response = $request.GetResponse()
        $totalLength = [System.Math]::Floor($response.get_ContentLength() / 1024)
        $responseStream = $response.GetResponseStream()
        $targetStream = New-Object -TypeName System.IO.FileStream -ArgumentList $file, Create
        $buffer = new-object byte[] 10KB
        $count = $responseStream.Read($buffer, 0, $buffer.length)
        $downloadedBytes = $count

        while ($count -gt 0) {
            $targetStream.Write($buffer, 0, $count)
            $count = $responseStream.Read($buffer, 0, $buffer.length)
            $downloadedBytes = $downloadedBytes + $count
            $status = "Downloaded ($([System.Math]::Floor($downloadedBytes/1024))K of $($totalLength)K): "
            $percentComplete = ((([System.Math]::Floor($downloadedBytes / 1024)) / $totalLength) * 100)
            $activity = "Downloading file '$($url.split('/') | Select -Last 1)'"
            Write-Progress -activity $activity -status $status -PercentComplete $percentComplete
        }

        Write-Progress -activity "Finished downloading file '$($url.split('/') | Select -Last 1)'"
    }
    catch [System.SystemException] {
        Write-Error "Unable to download $file from $url : $($PSItem.ToString())" -ErrorAction Stop
    }
    finally {
        $targetStream.Flush()
        $targetStream.Close()
        $targetStream.Dispose()
        $responseStream.Dispose()
    }
}

function Download-Srcclr {
    param(
        [Parameter(ValueFromPipeline)]$version
    )
    $srcclrTemp = Join-Path $CacheDir "srcclr-$version-windows.zip"
    if ([System.IO.File]::Exists($srcclrTemp)) {
        Write-Debug "Lightman zip already exists at $srcclrTemp, skipping download..."
        return $srcclrTemp
    }
    Write-Debug "Fetching version $version of Lightman and writing to $srcclrTemp"
    $url = "$DownloadUrl/srcclr-$version-windows.zip"
    Download-File $url $srcclrTemp
    return $srcclrTemp
}

function Download-7zip {
    param (
        [string]$destination
    )
    if ([System.IO.File]::Exists($destination)) {
        Write-Debug "7zip already exists, skipping download..."
        return
    }
    Write-Debug 'Downloading 7zip'
    Download-File "$DownloadUrl/7za.exe" $destination
}

# Code taken from chocolatey.org/install.ps1
function Unzip {
    param(
        [Parameter(ValueFromPipeline)]$path
    )

    $srcclrInstallPath = Join-Path $CacheDir "srcclr-$SrcclrVersion"
    $srcclrCompletedPath = Join-Path $srcclrInstallPath 'completed'
    if (Test-Path $srcclrCompletedPath) {
        Write-Debug "Lightman is already extracted"
        return
    }

    try {
        # We first try to use Expand-Archive because the use of 7za.exe may be flagged
        # as a security violation in some platform
        Write-Debug "Unzipping $path into $CacheDir"
        Expand-Archive -DestinationPath "$CacheDir" -Path "$path" -Force
        
        # We signal the completion of the install by inserting a 'completed'
        # file into the SourceClear installation directory.
        echo $null >> $srcclrCompletedPath
        Write-Debug "Successfully extracted $path to $CacheDir"
    } catch {
        # We use 7zip to unzip the agent because it's the most reliable
        # way to unzip files across windows and powershell versions.
        # 7za.exe is taken from 7-Zip Extra: standalone console version 18.05 (2018-04-30)
        $7zaExe = Join-Path $CacheDir '7za.exe'
        Download-7zip $7zaExe

        $params = "x -o`"$CacheDir`" -bd -y `"$path`""
        Write-Debug "Unzipping $path into $CacheDir"
        # use more robust Process as compared to Start-Process -Wait (which doesn't
        # wait for the process to finish in PowerShell v3)
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = New-Object System.Diagnostics.ProcessStartInfo($7zaExe, $params)
        $process.StartInfo.RedirectStandardOutput = $true
        $process.StartInfo.UseShellExecute = $false
        $process.StartInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
        $process.Start() | Out-Null
        $process.BeginOutputReadLine()
        $process.WaitForExit()
        $exitCode = $process.ExitCode
        $process.Dispose()

        Write-Debug "7zip exited with $exitCode"
        switch ($exitCode) {
            0 {
                # We signal the completion of the install by inserting a
                #  'completed' file into the SourceClear installation
                #  directory.
                echo $null >> $srcclrCompletedPath
                Write-Debug "Successfully extracted $path to $CacheDir"
            }
            default { throw "$errorMessage 7-zip couldn't unzip $path (code: $exitCode)" }
        }
    }
}

function Main {
    # Set powershell debugging to true when --debug is passed to the script
    foreach ($arg in $args) {
        if ($arg -eq '--debug') {
            $DebugPreference = 'Continue'
        }
    }

    $SrcclrVersion | Download-Srcclr | Unzip
    $srcclrScriptPath = Join-Path $CacheDir "srcclr-$SrcclrVersion" | Join-Path -ChildPath 'bin' | Join-Path -ChildPath 'srcclr'

    $argString = ''
    foreach ($arg in $args) {
        $argString = "$argString $arg"
    }
    Write-Debug "Invoking $srcclrScriptPath with 'srcclr $argString'"

    & "$srcclrScriptPath" $args
}

set-alias srcclr -value Main

# Execute Main only when arguments are passed into the script
if (!($args.count -eq 0)) {
    Main @args
}