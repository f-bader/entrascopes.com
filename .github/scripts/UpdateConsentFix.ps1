[CmdletBinding()]
param ()

# Load the JSON file
$jsonPath = Join-Path -Path $PSScriptRoot -ChildPath "..\..\firstpartyscopes.json"
$json = Get-Content -Path $jsonPath | ConvertFrom-Json

# Array to store results
$results = @()

# Cache for DNS lookups
$dnsCache = @{}

# Iterate through all apps
foreach ($appId in $json.apps.PSObject.Properties.Name) {
    $app = $json.apps.$appId
    
    # Skip if no redirect_uris
    if (-not $app.redirect_uris) {
        continue
    }
    
    # Check each redirect URI
    foreach ($redirectUri in $app.redirect_uris) {
        $affectedReferer = $null
        
        # Criterion 1: Check for localhost referer
        if ($redirectUri -match 'localhost') {
            $affectedReferer = $redirectUri
        }
        
        # Criterion 2: Check for non-http/https schema that only works on mobile
        # This includes: msauth://, x-msauth-*, msal*, msauth.com.*, ms-appx-web://, ms-app://, urn:, etc.
        elseif ( $redirectUri -match '^(?!https?://)' ) {
            $affectedReferer = $redirectUri
        }
        
        # Criterion 3: Check if domain is not publicly resolvable
        # Extract domain/hostname from the URI
        else {
            try {
                if ($redirectUri -match '^https?://') {
                    Write-Verbose "Processing URI: $redirectUri"
                    $RedirectHost = [System.Uri]"$redirectUri" | Select-Object -ExpandProperty Host -ErrorAction Stop
                    Write-Verbose "Extracted host: $RedirectHost"
                    
                    # Check cache first
                    if ($dnsCache.ContainsKey($RedirectHost)) {
                        if ($dnsCache[$RedirectHost]) {
                            # Domain is known to be resolvable
                            continue
                        } else {
                            # Domain is known to be unresolvable
                            $affectedReferer = $redirectUri
                        }
                    } else {
                        # Try to resolve the domain
                        try {
                            $resolved = [System.Net.Dns]::GetHostAddresses($RedirectHost)
                            # Domain is publicly resolvable, cache as true and skip
                            $dnsCache[$RedirectHost] = $true
                            continue
                        }
                        catch {
                            # Domain is not publicly resolvable, cache as false
                            $dnsCache[$RedirectHost] = $false
                            $affectedReferer = $redirectUri
                        }
                    }
                }
            }
            catch {
                Write-Verbose "Failed to parse URI: $redirectUri - $($_.Exception.Message)"
                # If we can't parse it, skip
                continue
            }
        }
        
        # If any criterion was met, add to results
        if ($affectedReferer) {
            $results += @{
                AppId = $appId
                AppName = $app.name
                AffectedReferer = $affectedReferer
                Reason = if ($affectedReferer -match 'localhost') {
                    "Local host referer"
                }
                elseif ($affectedReferer -match '^(?!https?://)' -and ($affectedReferer -match 'msauth|x-msauth|msal|ms-appx|ms-app|urn:')) {
                    "Non-standard schema (mobile only)"
                }
                else {
                    "Non-publicly resolvable domain"
                }
            }
        }
    }
}

# Convert to JSON and output
$jsonOutput = $results | ConvertTo-Json -Depth 10
Write-Output $jsonOutput

# Optionally save to file
$outputPath = Join-Path -Path $PSScriptRoot -ChildPath "..\..\constentfix.json"
$jsonOutput | Set-Content -Path $outputPath -Encoding UTF8

Write-Host "Results saved to: $outputPath"
Write-Host "Total affected apps found: $($results.Count)"
