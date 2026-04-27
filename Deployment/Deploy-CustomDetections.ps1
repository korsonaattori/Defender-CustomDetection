<#
.SYNOPSIS
    Deploy Custom Detection Rules to Microsoft Defender XDR
.DESCRIPTION
    This script deploys all custom detection rules from the repository to Microsoft Defender XDR.
    It validates, imports, and configures each detection rule with appropriate settings.
.NOTES
    Requires: Microsoft Defender XDR PowerShell module
    Run as: Security Administrator or Global Administrator
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$RulePath = "../CustomDetectionRules",
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf,
    
    [Parameter(Mandatory=$false)]
    [switch]$Force
)

#Requires -Module Microsoft.Graph

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("Info", "Warning", "Error", "Success")]
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "Info"    { "White" }
        "Warning" { "Yellow" }
        "Error"   { "Red" }
        "Success" { "Green" }
    }
    
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

function Test-Prerequisites {
    Write-Log "Checking prerequisites..." -Level Info
    
    # Check for required modules
    $requiredModules = @("Microsoft.Graph")
    foreach ($module in $requiredModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            Write-Log "Required module not found: $module" -Level Error
            Write-Log "Install with: Install-Module $module -Force" -Level Warning
            return $false
        }
    }
    
    # Check for Microsoft Defender XDR connection
    try {
        $context = Get-MgContext
        if (-not $context) {
            Write-Log "Not connected to Microsoft Graph" -Level Error
            Write-Log "Run: Connect-MgGraph -Scopes 'SecurityEvents.ReadWrite.All'" -Level Warning
            return $false
        }
        Write-Log "Connected to Microsoft Graph as: $($context.Account)" -Level Success
    }
    catch {
        Write-Log "Failed to check Graph connection: $_" -Level Error
        return $false
    }
    
    # Check rule path exists
    if (-not (Test-Path $RulePath)) {
        Write-Log "Rule path not found: $RulePath" -Level Error
        return $false
    }
    
    return $true
}

function Import-DetectionRule {
    param(
        [string]$RuleFile,
        [switch]$WhatIf
    )
    
    Write-Log "Processing: $RuleFile" -Level Info
    
    try {
        [xml]$RuleXml = Get-Content $RuleFile
        
        foreach ($rule in $RuleXml.DetectionRules.DetectionRule) {
            Write-Log "  Importing rule: $($rule.Name)" -Level Info
            Write-Log "    ID: $($rule.ID)" -Level Info
            Write-Log "    Severity: $($rule.Severity)" -Level Info
            Write-Log "    Confidence: $($rule.ConfidenceLevel)" -Level Info
            
            if ($WhatIf) {
                Write-Log "    [WhatIf] Would create detection rule" -Level Warning
                continue
            }
            
            # Build detection rule object
            $detectionRule = @{
                displayName = $rule.Name
                description = $rule.Description
                severity = $rule.Severity
                enabled = $true
                tactics = $rule.Tactics -split ', ' | Where-Object { $_ }
                techniques = $rule.Techniques -split ', ' | Where-Object { $_ }
                query = $rule.DetectionLogic.InnerText.Trim()
                queryFrequency = "PT1H"
                queryPeriod = "PT1H"
                triggerOperator = "GreaterThan"
                triggerThreshold = 0
            }
            
            # Check if rule already exists
            $existingRules = Get-MgSecurityDetectionRule -All
            $existingRule = $existingRules | Where-Object { $_.DisplayName -eq $rule.Name }
            
            if ($existingRule) {
                Write-Log "    Rule already exists, updating..." -Level Warning
                
                if (-not $Force) {
                    $confirm = Read-Host "Update rule '$($rule.Name)'? (Y/N)"
                    if ($confirm -ne 'Y') {
                        Write-Log "    Skipped" -Level Info
                        continue
                    }
                }
                
                try {
                    Update-MgSecurityDetectionRule `
                        -DetectionRuleId $existingRule.Id `
                        @detectionRule
                    Write-Log "    Rule updated successfully" -Level Success
                }
                catch {
                    Write-Log "    Failed to update rule: $_" -Level Error
                }
            }
            else {
                Write-Log "    Creating new rule..." -Level Info
                
                try {
                    New-MgSecurityDetectionRule @detectionRule
                    Write-Log "    Rule created successfully" -Level Success
                }
                catch {
                    Write-Log "    Failed to create rule: $_" -Level Error
                }
            }
        }
    }
    catch {
        Write-Log "Failed to process rule file: $RuleFile" -Level Error
        Write-Log "Error: $_" -Level Error
    }
}

function Get-DeploymentSummary {
    param(
        [string]$RulePath
    )
    
    $totalRules = 0
    $ruleFiles = Get-ChildItem -Path $RulePath -Filter "*.xml"
    
    Write-Log "`nDeployment Summary" -Level Info
    Write-Log "==================" -Level Info
    
    foreach ($file in $ruleFiles) {
        [xml]$xml = Get-Content $file.FullName
        $ruleCount = $xml.DetectionRules.DetectionRule.Count
        $totalRules += $ruleCount
        
        $severitySummary = @{}
        foreach ($rule in $xml.DetectionRules.DetectionRule) {
            $severity = $rule.Severity
            if ($severitySummary.ContainsKey($severity)) {
                $severitySummary[$severity]++
            }
            else {
                $severitySummary[$severity] = 1
            }
        }
        
        Write-Log "  $($file.Name): $ruleCount rules" -Level Info
        foreach ($severity in $severitySummary.Keys) {
            Write-Log "    $severity: $($severitySummary[$severity])" -Level Info
        }
    }
    
    Write-Log "  Total: $totalRules rules" -Level Success
    Write-Log ""
    
    return $totalRules
}

# Main execution
Write-Log "==========================================" -Level Info
Write-Log "Microsoft Defender XDR Custom Detection Deployment" -Level Info
Write-Log "==========================================" -Level Info
Write-Log ""

# Check prerequisites
if (-not (Test-Prerequisites)) {
    Write-Log "Prerequisites check failed. Exiting." -Level Error
    exit 1
}

Write-Log ""

# Show deployment summary
$totalRules = Get-DeploymentSummary -RulePath $RulePath

if (-not $WhatIf) {
    Write-Log "Deploy $totalRules detection rules? (Y/N)" -Level Warning
    $confirm = Read-Host
    
    if ($confirm -ne 'Y') {
        Write-Log "Deployment cancelled." -Level Warning
        exit 0
    }
}
else {
    Write-Log "Running in WhatIf mode - no changes will be made" -Level Warning
}

Write-Log ""
Write-Log "Starting deployment..." -Level Info
Write-Log ""

# Process all XML rule files
$ruleFiles = Get-ChildItem -Path $RulePath -Filter "*.xml" | Sort-Object Name
$successCount = 0
$failCount = 0

foreach ($ruleFile in $ruleFiles) {
    Import-DetectionRule -RuleFile $ruleFile.FullName -WhatIf:$WhatIf
    
    # Count success/failure based on output (simplified)
    $successCount++
}

Write-Log ""
Write-Log "==========================================" -Level Info
Write-Log "Deployment Complete" -Level Success
Write-Log "Processed: $($ruleFiles.Count) files" -Level Info
Write-Log "==========================================" -Level Info
Write-Log ""
Write-Log "Next steps:" -Level Info
Write-Log "1. Review deployed rules in Microsoft Defender portal" -Level Info
Write-Log "2. Configure alert thresholds as needed" -Level Info
Write-Log "3. Test rules in alert-only mode initially" -Level Info
Write-Log "4. Monitor for false positives and adjust" -Level Info
Write-Log ""
