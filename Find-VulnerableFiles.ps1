param(
    [Parameter(Mandatory=$false, Position=0, HelpMessage="Path to the file containing vulnerable file paths")]
    [ValidateScript({
        if ($_ -and -not (Test-Path $_ -PathType Leaf)) {
            throw "File '$_' does not exist."
        }
        return $true
    })]
    [string]$ListFile,
    
    [Parameter(HelpMessage="Export results to CSV file")]
    [string]$OutputFile,
    
    [Parameter(HelpMessage="Export results to TXT file")]
    [string]$TextOutputFile,
    
    [Parameter(HelpMessage="Show only found files (suppress not found messages)")]
    [switch]$FoundOnly,
    
    [Parameter(HelpMessage="Show help information")]
    [switch]$Help
)

<#
.SYNOPSIS
    Searches for potentially vulnerable files on the local system.

.DESCRIPTION
    This script reads a list of vulnerable file paths from a text file and searches for their existence
    on the local system. It expands environment variables and handles version wildcards to locate
    potentially vulnerable files that security researchers can use to create detections.

.PARAMETER ListFile
    Path to the text file containing vulnerable file paths (one per line).
    Environment variables like %PROGRAMFILES%, %SYSTEM32% will be expanded.

.PARAMETER OutputFile
    Optional. Path to export results to a CSV file.

.PARAMETER TextOutputFile
    Optional. Path to export results to a TXT file.

.PARAMETER FoundOnly
    Optional. Show only files that were found (suppress "not found" messages).


.PARAMETER Help
    Optional. Display this help information.

.EXAMPLE
    .\Find-VulnerableFiles.ps1 -ListFile "vulnerable_files.txt"
    
    Searches for all Files listed in vulnerable_Files.txt and displays results.

.EXAMPLE
    .\Find-VulnerableFiles.ps1 -ListFile "vulnerable_Files.txt" -OutputFile "results.csv" -FoundOnly
    
    Searches for Files, shows only found ones, and exports results to CSV.

.EXAMPLE
    .\Find-VulnerableFiles.ps1 -ListFile "vulnerable_Files.txt" -TextOutputFile "results.txt" 
    
    Searches for Files with verbose output and exports results to a text file.

.EXAMPLE
    .\Find-VulnerableFiles.ps1 -ListFile "vulnerable_Files.txt" -OutputFile "results.csv" -TextOutputFile "results.txt"
    
    Searches for Files and exports results to both CSV and TXT formats.

.NOTES
    Author: Security Research Assistant
    Purpose: Help security researchers identify vulnerable Files for detection creation
    
    Environment Variables Supported:
    - %PROGRAMFILES% / %PROGRAMFILES(X86)%
    - %SYSTEM32% / %SYSWOW64%
    - %WINDIR% / %WINDOWS%
    - %APPDATA% / %LOCALAPPDATA%
    - %USERPROFILE%
    - %PROGRAMDATA%
    - %VERSION% (handled as wildcard)

.LINK
    https://github.com/example
#>

# Function to display help information
function Show-Help {
    Write-Host ""
    Write-Host "Vulnerable File Scanner" -ForegroundColor Cyan
    Write-Host "=====================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "USAGE:" -ForegroundColor Yellow
    Write-Host "    .\Find-VulnerableFiles.ps1 -ListFile <path> [options]" -ForegroundColor White
    Write-Host ""
    Write-Host "REQUIRED PARAMETERS:" -ForegroundColor Yellow
    Write-Host "    -ListFile <path>      Path to file containing vulnerable File paths (one per line)" -ForegroundColor White
    Write-Host ""
    Write-Host "OPTIONAL PARAMETERS:" -ForegroundColor Yellow
    Write-Host "    -OutputFile <path>       Export results to CSV file" -ForegroundColor White
    Write-Host "    -TextOutputFile <path>   Export results to TXT file" -ForegroundColor White
    Write-Host "    -FoundOnly               Show only found Files (suppress not found messages)" -ForegroundColor White
    Write-Host "    -Help                    Show this help information" -ForegroundColor White
    Write-Host ""
    Write-Host "EXAMPLES:" -ForegroundColor Yellow
    Write-Host "    .\Find-VulnerableFiles.ps1 -ListFile 'vulnerable_Files.txt'" -ForegroundColor Gray
    Write-Host "    .\Find-VulnerableFiles.ps1 -ListFile 'Files.txt' -OutputFile 'results.csv' -FoundOnly" -ForegroundColor Gray
    Write-Host "    .\Find-VulnerableFiles.ps1 -ListFile 'Files.txt' -TextOutputFile 'results.txt' " -ForegroundColor Gray
    Write-Host "    .\Find-VulnerableFiles.ps1 -ListFile 'Files.txt' -OutputFile 'results.csv' -TextOutputFile 'results.txt'" -ForegroundColor Gray
    Write-Host ""
    Write-Host "For detailed help, use: Get-Help .\Find-VulnerableFiles.ps1 -Full" -ForegroundColor Cyan
    Write-Host ""
}

# Check if no arguments provided or help requested
if ($Help -or (-not $ListFile -and $args.Count -eq 0)) {
    Show-Help
    return
}

# Check if ListFile is provided
if (-not $ListFile) {
    Write-Host "ERROR: ListFile parameter is required." -ForegroundColor Red
    Write-Host ""
    Show-Help
    return
}

# Initialize counters and results
$foundFiles = @()
$notFoundFiles = @()
$totalChecked = 0
$startTime = Get-Date

Write-Host "Vulnerable File Scanner Started" -ForegroundColor Green
Write-Host "================================" -ForegroundColor Green
Write-Host "Start Time: $startTime"
Write-Host "Input File: $ListFile"
Write-Host ""

# Function to expand environment variables
function Expand-EnvironmentPath {
    param([string]$Path)
    
    # Replace common environment variables
    $expandedPath = $Path -replace '%PROGRAMFILES%', $env:ProgramFiles
    $expandedPath = $expandedPath -replace '%PROGRAMFILES\(X86\)%', ${env:ProgramFiles(x86)}
    $expandedPath = $expandedPath -replace '%SYSTEM32%', "$env:SystemRoot\System32"
    $expandedPath = $expandedPath -replace '%SYSWOW64%', "$env:SystemRoot\SysWOW64"
    $expandedPath = $expandedPath -replace '%WINDIR%', $env:SystemRoot
    $expandedPath = $expandedPath -replace '%WINDOWS%', $env:SystemRoot
    $expandedPath = $expandedPath -replace '%APPDATA%', $env:APPDATA
    $expandedPath = $expandedPath -replace '%LOCALAPPDATA%', $env:LOCALAPPDATA
    $expandedPath = $expandedPath -replace '%USERPROFILE%', $env:USERPROFILE
    $expandedPath = $expandedPath -replace '%PROGRAMDATA%', $env:PROGRAMDATA
    $expandedPath = $expandedPath -replace '<version>', "*"
    $expandedPath = $expandedPath -replace '<version_packageid>', "*"
    $expandedPath = $expandedPath -replace '<username>', "*"
    $expandedPath = $expandedPath -replace '%VERSION%', "*"


#%VERSION%

    # Convert forward slashes to backslashes
    $expandedPath = $expandedPath -replace '/', '\'
    
    return $expandedPath
}

# Function to handle version wildcards
function Get-PathsWithVersionWildcard {
    param([string]$Path)
    
    if ($Path -like '*%VERSION%*') {
        # Get the directory part before %VERSION%
        $basePath = $Path -replace '%VERSION%.*$', ''
        $basePath = Expand-EnvironmentPath $basePath
        
        # Get the part after %VERSION%
        $afterVersion = $Path -replace '^.*%VERSION%', ''
        
        $foundPaths = @()
        
        if (Test-Path $basePath) {
            # Get all subdirectories and try to construct the full path
            $subdirs = Get-ChildItem $basePath -Directory -ErrorAction SilentlyContinue
            foreach ($subdir in $subdirs) {
                $testPath = Join-Path $subdir.FullName $afterVersion
                $foundPaths += $testPath
            }
        }
        
        return $foundPaths
    } else {
        # No version wildcard, just expand normally
        return @(Expand-EnvironmentPath $Path)
    }
}

# Function to export results to text file
function Export-ToTextFile {
    param(
        [array]$FoundFiles,
        [array]$NotFoundFiles,
        [string]$FilePath,
        [datetime]$StartTime,
        [datetime]$EndTime
    )
    
    try {
        $content = @()
        $content += "Vulnerable File Scanner Results"
        $content += "=============================="
        $content += "Scan Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        $content += "Start Time: $StartTime"
        $content += "End Time: $EndTime"
        $content += "Duration: $($EndTime - $StartTime)"
        $content += "Total paths checked: $($FoundFiles.Count + $NotFoundFiles.Count)"
        $content += "Files found: $($FoundFiles.Count)"
        $content += "Files not found: $($NotFoundFiles.Count)"
        $content += ""
        
        if ($FoundFiles.Count -gt 0) {
            $content += "VULNERABLE Files FOUND:"
            $content += "======================"
            $content += ""
            
            foreach ($File in $FoundFiles) {
                $content += "FOUND: $($File.ExpandedPath)"
                $content += "  Original Path: $($File.OriginalPath)"
                if ($File.Version) {
                    $content += "  Version: $($File.Version)"
                }
                $content += "  Size: $($File.FileSize) bytes"
                $content += "  Modified: $($File.LastWriteTime)"
                $content += ""
            }
        }
        
        if ($NotFoundFiles.Count -gt 0) {
            $content += "Files NOT FOUND:"
            $content += "==============="
            $content += ""
            
            foreach ($File in $NotFoundFiles) {
                $content += "NOT FOUND: $($File.OriginalPath)"
                $content += "  Checked Path: $($File.ExpandedPath)"
                $content += ""
            }
        }
        
        $content += "End of Report"
        $content += "============="
        
        $content | Out-File -FilePath $FilePath -Encoding UTF8
        Write-Host "Text results exported to: $FilePath" -ForegroundColor Green
        
    } catch {
        Write-Error "Failed to export text results: $_"
    }
}

# Read the File list file
try {
    $FilePaths = Get-Content $ListFile -ErrorAction Stop
    Write-Host "Loaded $($FilePaths.Count) File paths from file." -ForegroundColor Yellow
    Write-Host ""
} catch {
    Write-Error "Failed to read File list file: $_"
    exit 1
}

# Process each File path
foreach ($FilePath in $FilePaths) {
    # Skip empty lines and comments
    if ([string]::IsNullOrWhiteSpace($FilePath) -or $FilePath.StartsWith('#')) {
        continue
    }
    
    $totalChecked++
    
    # Handle version wildcards and expand environment variables
    $expandedPaths = Get-PathsWithVersionWildcard $FilePath
    
    $found = $false
    $invalidChars = [System.IO.Path]::GetInvalidPathChars()

foreach ($expandedPath in $expandedPaths) {
    Write-Verbose "Checking: $expandedPath"

    if ($expandedPath.IndexOfAny($invalidChars) -ne -1) {
        Write-Warning "Skipping invalid path (contains illegal characters): $expandedPath"
        continue
    }

    if (Test-Path $expandedPath -PathType Leaf) {
            $fileInfo = Get-Item $expandedPath
            $result = [PSCustomObject]@{
                OriginalPath = $FilePath
                ExpandedPath = $expandedPath
                Found = $true
                FileSize = $fileInfo.Length
                LastWriteTime = $fileInfo.LastWriteTime
                Version = $fileInfo.VersionInfo.FileVersion
            }
            
            $foundFiles += $result
            Write-Host "[FOUND] $expandedPath" -ForegroundColor Red
            $found = $true
            break  # Found one instance, no need to check other version paths
        }
    }
    
    if (-not $found) {
    $firstAttemptedPath = if ($expandedPaths -and $expandedPaths.Count -gt 0) { $expandedPaths[0] } else { "N/A" }

    $result = [PSCustomObject]@{
        OriginalPath = $FilePath
        ExpandedPath = $firstAttemptedPath
        Found = $false
        FileSize = $null
        LastWriteTime = $null
        Version = $null
    }
        
        $notFoundFiles += $result
        
        if (-not $FoundOnly) {
            Write-Host "[NOT FOUND] $FilePath" -ForegroundColor Green
        }
    }
    
    # Progress indicator
    if ($totalChecked % 50 -eq 0) {
        Write-Host "Progress: $totalChecked paths checked..." -ForegroundColor Yellow
    }
}

# Summary
$endTime = Get-Date
$duration = $endTime - $startTime

Write-Host ""
Write-Host "Scan Complete" -ForegroundColor Green
Write-Host "=============" -ForegroundColor Green
Write-Host "End Time: $endTime"
Write-Host "Duration: $($duration.TotalSeconds) seconds"
Write-Host "Total paths checked: $totalChecked"
Write-Host "Files found: $($foundFiles.Count)" -ForegroundColor Red
Write-Host "Files not found: $($notFoundFiles.Count)" -ForegroundColor Green
Write-Host ""

if ($foundFiles.Count -gt 0) {
    Write-Host "VULNERABLE Files FOUND:" -ForegroundColor Red -BackgroundColor Yellow
    Write-Host "======================" -ForegroundColor Red -BackgroundColor Yellow
    foreach ($File in $foundFiles) {
        Write-Host "$($File.ExpandedPath)" -ForegroundColor Red
        if ($File.Version) {
            Write-Host "  Version: $($File.Version)" -ForegroundColor Yellow
        }
        Write-Host "  Size: $($File.FileSize) bytes" -ForegroundColor Yellow
        Write-Host "  Modified: $($File.LastWriteTime)" -ForegroundColor Yellow
        Write-Host ""
    }
}

# Export to CSV if requested
if ($OutputFile) {
    try {
        $allResults = $foundFiles + $notFoundFiles
        $allResults | Export-Csv $OutputFile -NoTypeInformation
        Write-Host "CSV results exported to: $OutputFile" -ForegroundColor Green
    } catch {
        Write-Error "Failed to export CSV results: $_"
    }
}

# Export to TXT if requested
if ($TextOutputFile) {
    Export-ToTextFile -FoundFiles $foundFiles -FilePath $TextOutputFile 
}

# Exit with appropriate code
if ($foundFiles.Count -gt 0) {
    Write-Host "WARNING: Potentially vulnerable LOLBins were found on this system!" -ForegroundColor Red -BackgroundColor Yellow
    exit 1
} else {
    Write-Host "No vulnerable LOLBins found on this system." -ForegroundColor Green
    exit 0
}