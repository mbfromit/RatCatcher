function Submit-ScanToApi {
    param(
        [string]$ApiUrl,
        [string]$Password,
        [string]$Hostname,
        [string]$Username,
        [string]$ScanTimestamp,
        [string]$Duration,
        [string]$Verdict,
        [int]$ProjectsScanned,
        [int]$VulnerableCount,
        [int]$CriticalCount,
        [string]$PathsScanned,
        [string]$BriefPath,
        [string]$ReportPath
    )

    if ([string]::IsNullOrEmpty($Password)) {
        return @{ Status = 'skipped' }
    }

    try {
        # Use .NET HttpClient directly — avoids both the quoted-boundary issue
        # in Invoke-RestMethod -Form AND the empty-file issue on macOS/Linux
        $httpClient = [System.Net.Http.HttpClient]::new()
        $form = [System.Net.Http.MultipartFormDataContent]::new()

        # Add text fields
        $fields = [ordered]@{
            password         = $Password
            hostname         = $Hostname
            username         = $Username
            scan_timestamp   = $ScanTimestamp
            duration         = $Duration
            verdict          = $Verdict
            projects_scanned = [string]$ProjectsScanned
            vulnerable_count = [string]$VulnerableCount
            critical_count   = [string]$CriticalCount
            paths_scanned    = $PathsScanned
        }
        foreach ($key in $fields.Keys) {
            $form.Add([System.Net.Http.StringContent]::new($fields[$key]), $key)
        }

        # Add file fields
        foreach ($file in @(
            @{ Name = 'brief';  Path = $BriefPath  },
            @{ Name = 'report'; Path = $ReportPath }
        )) {
            $fileBytes   = [System.IO.File]::ReadAllBytes($file.Path)
            $fileContent = [System.Net.Http.ByteArrayContent]::new($fileBytes)
            $fileContent.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::new('text/html')
            $fileName    = [System.IO.Path]::GetFileName($file.Path)
            $form.Add($fileContent, $file.Name, $fileName)
        }

        # Fix the quoted boundary — Cloudflare Workers cannot parse boundary="xxx"
        # Extract the boundary from the content type and rebuild without quotes
        $ct = $form.Headers.ContentType.ToString()
        $ct = $ct -replace 'boundary="([^"]+)"', 'boundary=$1'
        $form.Headers.Remove('Content-Type') | Out-Null
        $form.Headers.TryAddWithoutValidation('Content-Type', $ct) | Out-Null

        $response = $httpClient.PostAsync($ApiUrl, $form).GetAwaiter().GetResult()
        $body     = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()

        if ($response.IsSuccessStatusCode) {
            $parsed = $body | ConvertFrom-Json
            return @{ Status = 'success'; Id = $parsed.id }
        } elseif ($response.StatusCode.value__ -eq 401) {
            return @{ Status = 'wrong-password' }
        } else {
            return @{ Status = 'error'; Message = "HTTP $($response.StatusCode.value__): $body" }
        }
    }
    catch {
        return @{ Status = 'error'; Message = $_.ToString() }
    }
    finally {
        if ($httpClient) { $httpClient.Dispose() }
        if ($form)       { $form.Dispose() }
    }
}
