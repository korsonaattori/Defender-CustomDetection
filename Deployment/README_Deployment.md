# Deployment Guide - Custom Detection Rules

## Overview

This guide provides step-by-step instructions for deploying custom detection rules to Microsoft Defender XDR.

## Prerequisites

### Required Permissions

- **Security Administrator** or **Global Administrator** role in Entra ID
- **Microsoft Defender XDR** license (Plan 1 or Plan 2)

### Required Modules

```powershell
# Install Microsoft Graph module
Install-Module Microsoft.Graph -Force

# Import the module
Import-Module Microsoft.Graph
```

## Deployment Steps

### Step 1: Connect to Microsoft Graph

```powershell
# Connect with required scopes
Connect-MgGraph -Scopes @(
    "SecurityEvents.ReadWrite.All",
    "Policy.ReadWrite.All",
    "Directory.Read.All"
)

# Verify connection
Get-MgContext
```

### Step 2: Review Detection Rules

Before deploying, review each detection rule file:

```powershell
# List all detection rule files
Get-ChildItem -Path ".\CustomDetectionRules" -Filter "*.xml"

# Review a specific rule
[xml]$rule = Get-Content ".\CustomDetectionRules\Ransomware_Detections.xml"
$rule.DetectionRules.DetectionRule | Format-Table Name, Severity, ConfidenceLevel
```

### Step 3: Test Deployment (WhatIf Mode)

Run the deployment script in test mode to see what would be created:

```powershell
cd ".\Deployment"
.\Deploy-CustomDetections.ps1 -WhatIf
```

### Step 4: Deploy Detection Rules

Execute the deployment script:

```powershell
# Deploy all rules
.\Deploy-CustomDetections.ps1

# Deploy with force (skip confirmations)
.\Deploy-CustomDetections.ps1 -Force

# Deploy from custom path
.\Deploy-CustomDetections.ps1 -RulePath "C:\CustomRules"
```

### Step 5: Verify Deployment

Check that rules were created successfully:

```powershell
# Get all custom detection rules
Get-MgSecurityDetectionRule | Where-Object { $_.DisplayName -like "*CUSTOM*" }

# Check specific rule
Get-MgSecurityDetectionRule -DetectionRuleId "CUSTOM-RANS-001"

# Verify rule count
(Get-MgSecurityDetectionRule | Where-Object { $_.DisplayName -like "*CUSTOM*" }).Count
```

## Rule Configuration

### Adjusting Alert Thresholds

After deployment, you may need to adjust alert thresholds:

```powershell
# Update rule threshold
Update-MgSecurityDetectionRule `
    -DetectionRuleId "CUSTOM-RANS-001" `
    -TriggerThreshold 5
```

### Enabling/Disabling Rules

```powershell
# Disable a rule
Update-MgSecurityDetectionRule `
    -DetectionRuleId "CUSTOM-RANS-001" `
    -Enabled $false

# Enable a rule
Update-MgSecurityDetectionRule `
    -DetectionRuleId "CUSTOM-RANS-001" `
    -Enabled $true
```

### Configuring Alert Suppression

```powershell
# Set suppression duration
Update-MgSecurityDetectionRule `
    -DetectionRuleId "CUSTOM-RANS-001" `
    -SuppressionDuration "PT1H"
```

## Advanced Configuration

### Integration with Microsoft Sentinel

1. **Create Analytics Rule:**
   ```kql
   // In Microsoft Sentinel
   SecurityAlert
   | where ProviderName == "MDATP"
   | where AlertName contains "CUSTOM"
   | project TimeGenerated, AlertName, Severity, Entities
   ```

2. **Configure Alert Automation:**
   - Go to Microsoft Sentinel → Analytics → Active Rules
   - Create automation rule for custom detections
   - Configure severity-based routing

### Integration with SOAR Platforms

**ServiceNow Integration:**
```powershell
# Configure webhook in Defender XDR
# Route alerts to ServiceNow for incident creation
```

**Splunk Integration:**
```powershell
# Forward alerts to Splunk
# Use Splunk Add-on for Microsoft Defender
```

## Monitoring and Maintenance

### Daily Checks

```powershell
# Check for triggered alerts
Get-MgSecurityAlert `
    -Filter "severity eq 'High' or severity eq 'Critical'" `
    -Top 10
```

### Weekly Reviews

```powershell
# Review alert effectiveness
$StartDate = (Get-Date).AddDays(-7)
Get-MgSecurityAlert `
    -Filter "createdDateTime ge $StartDate" `
    | Group-Object DisplayName
```

### Monthly Tuning

```powershell
# Analyze false positive rates
Get-MgSecurityAlert `
    -Filter "severity eq 'High'" `
    | Where-Object { $_.Status -eq "Resolved" -and $_.Classification -eq "FalsePositive" }
    | Group-Object DisplayName
```

## Troubleshooting

### Rule Not Firing

**Check 1: Verify rule is enabled**
```powershell
Get-MgSecurityDetectionRule -DetectionRuleId "CUSTOM-RANS-001" | Select-Object Enabled
```

**Check 2: Review query syntax**
```powershell
# Test query in Advanced Hunting
# Copy query from rule definition and run in Advanced Hunting portal
```

**Check 3: Verify data coverage**
```powershell
# Check if relevant events are being logged
DeviceProcessEvents
| where Timestamp > ago(1h)
| where FileName == "powershell.exe"
| count
```

### High False Positive Rate

**Adjust threshold:**
```powershell
Update-MgSecurityDetectionRule `
    -DetectionRuleId "CUSTOM-RANS-001" `
    -TriggerThreshold 10  # Increase from default
```

**Add suppression:**
```powershell
Update-MgSecurityDetectionRule `
    -DetectionRuleId "CUSTOM-RANS-001" `
    -SuppressionDuration "PT2H"
```

### Permission Errors

**Required permissions:**
```powershell
# Reconnect with proper scopes
Disconnect-MgGraph
Connect-MgGraph -Scopes @(
    "SecurityEvents.ReadWrite.All",
    "Policy.ReadWrite.All"
)
```

## Best Practices

### Deployment Strategy

1. **Test Environment First:** Always test in non-production
2. **Phased Rollout:** Deploy 5-10 rules per week
3. **Monitor Closely:** Review alerts daily for first two weeks
4. **Document Exceptions:** Track legitimate activities that trigger alerts

### Alert Management

- **Triage Within 1 Hour:** For High and Critical severity alerts
- **Resolve Within 24 Hours:** For confirmed incidents
- **Review Weekly:** Analyze false positive rates
- **Tune Monthly:** Adjust thresholds based on organizational context

### Documentation

- **Maintain Inventory:** Track all deployed rules
- **Version Control:** Track rule changes and updates
- **Exception Tracking:** Document approved exceptions
- **Lessons Learned:** Capture and share improvements

## Rollback Procedures

### Disable All Custom Rules

```powershell
Get-MgSecurityDetectionRule `
    | Where-Object { $_.DisplayName -like "*CUSTOM*" } `
    | ForEach-Object {
        Update-MgSecurityDetectionRule `
            -DetectionRuleId $_.Id `
            -Enabled $false
    }
```

### Delete Specific Rule

```powershell
Remove-MgSecurityDetectionRule -DetectionRuleId "CUSTOM-RANS-001"
```

## Support Resources

- **Microsoft Documentation:** https://learn.microsoft.com/defender-xdr/
- **GitHub Repository:** https://github.com/org/defender-custom-detections
- **Issue Tracking:** https://github.com/org/defender-custom-detections/issues

## Success Metrics

| Metric | Target | Notes |
|--------|--------|-------|
| False Positive Rate | < 5% | After 30-day tuning |
| Mean Time to Detect | < 5 minutes | For critical threats |
| Alert Volume | 50-200/day | For 10,000+ endpoints |
| Coverage | 95%+ | Of MITRE techniques |

---

**Last Updated:** 2026-04-27  
**Version:** 1.0.0  
**Next Review:** 2026-07-27