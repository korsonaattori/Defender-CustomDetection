# Detection Tuning Guide

## Overview

This guide provides detailed information for tuning custom detection rules to optimize for your organization's specific environment and reduce false positives.

## Pre-Deployment Tuning

### Environment Assessment

Before deploying detection rules, assess your environment:

1. **Baseline Normal Activity**
   - Document typical PowerShell usage patterns
   - Identify authorized remote administration tools
   - Catalog legitimate scheduled tasks and services
   - Map normal network traffic patterns

2. **Identify Exceptions**
   - Backup systems and processes
   - Patch management tools
   - Legitimate penetration testing activities
   - Administrative jump boxes
   - Third-party management tools

3. **Define Tuning Strategy**
   - Time-based exclusions (maintenance windows)
   - User-based exclusions (IT administrators)
   - Process-based exclusions (authorized tools)
   - Network-based exclusions (management VLANs)

## Detection Rule Tuning

### Ransomware Detection Rules

#### CUSTOM-RANS-001: Rapid File Encryption

**Default Threshold:** 10 files in 5 minutes

**Tuning Recommendations:**

| Environment Size | Recommended Threshold | Rationale |
|------------------|----------------------|-----------|
| Small (<100 endpoints) | 5 files | Lower threshold for smaller environments |
| Medium (100-1000) | 10 files | Default threshold |
| Large (>1000) | 20 files | Higher threshold to reduce noise |

**Exclusions to Consider:**
- Backup software processes
- Legitimate encryption tools
- Database backup utilities
- File synchronization tools

**Implementation:**
```xml
<Threshold>20</Threshold>
<SuppressionDuration>PT1H</SuppressionDuration>
<ExcludeUsers>
  <User>BackupService*</User>
  <User>EncryptionAdmin*</User>
</ExcludeUsers>
```

#### CUSTOM-RANS-002: Shadow Copy Deletion

**Tuning Recommendations:**

**Legitimate Activities to Exclude:**
- Scheduled backup operations
- System maintenance windows
- Disaster recovery testing

**Time-Based Tuning:**
```xml
<!-- Only alert during non-backup hours -->
<TimeWindow>20:00-06:00</TimeWindow>
```

**Process Exclusions:**
- Windows Server Backup
- Veeam Backup
- CommVault
- NetBackup

#### CUSTOM-RANS-003: Suspicious Process Tree

**Parent-Child Exclusions:**

| Parent Process | Child Process | Action |
|----------------|---------------|---------|
| excel.exe | powershell.exe | MONITOR only |
| winword.exe | cmd.exe | ALERT |
| outlook.exe | wscript.exe | ALERT |

**Risk Scoring Adjustments:**

```xml
<!-- Lower risk for approved admin tools -->
<RiskAdjustment>
  <Process>mmc.exe</Process>
  <RiskReduction>20</RiskReduction>
</RiskAdjustment>
```

### Lateral Movement Detection Rules

#### CUSTOM-LAT-001: SMB Lateral Execution

**Service Account Exclusions:**

```xml
<ExcludeUsers>
  <User>*_svc$</User>
  <User>deploy_*</User>
  <User>admin_*</User>
</ExcludeUsers>
```

**Time-Based Tuning:**

| Activity Type | Recommended Window |
|---------------|-------------------|
| Workstation administration | Business hours only |
| Server administration | Extended hours |
| Automated deployments | Scheduled windows |

**Network Segmentation:**

```xml
<!-- Exclude management network -->
<ExcludeNetworks>
  <Network>10.100.0.0/24</Network>
</ExcludeNetworks>
```

#### CUSTOM-LAT-004: Pass-the-Hash Detection

**Tuning Considerations:**

**False Positive Sources:**
- Domain controller replication
- Administrative tools running across machines
- Legitimate service accounts

**Recommended Thresholds:**

```xml
<!-- Increase threshold for larger environments -->
<UniqueSources>5</UniqueSources>  <!-- Default: 3 -->
<LogonAttempts>10</LogonAttempts>  <!-- Default: 5 -->
```

**Exclusions:**
- Kerberos authentication (not NTLM)
- Service account usage patterns
- Domain controller traffic

### Credential Theft Detection Rules

#### CUSTOM-CRED-001: LSASS Memory Dump

**Legitimate Access Patterns:**

```xml
<AllowedProcesses>
  <Process>MsMpEng.exe</Process>  <!-- Windows Defender -->
  <Process>svchost.exe</Process>  <!-- System services -->
  <Process>lsass.exe</Process>    <!-- Self-access -->
</AllowedProcesses>
```

**Time-Based Adjustments:**

| Environment | Alert Window |
|-------------|-------------|
| 24/7 operations | Always alert |
| Business hours only | After hours only |
| Shift operations | All non-shift hours |

#### CUSTOM-CRED-002: SAM Registry Extraction

**Backup Operations:**

```xml
<!-- Allow backup window -->
<BackupWindow>
  <Start>02:00</Start>
  <End>04:00</End>
  <Days>Monday,Saturday</Days>
</BackupWindow>
```

**Authorized Tools:**
- System State Backup tools
- Disaster recovery utilities
- Forensic collection tools (with approval)

### Persistence Detection Rules

#### CUSTOM-PERS-001: Autorun Registry

**Common False Positives:**

| Key | Legitimate Use | Action |
|-----|----------------|---------|
| RunOnce | Software updates | MONITOR |
| RunOnceEx | System deployment | MONITOR |
| Run | User applications | MONITOR |

**Registry Exclusions:**

```xml
<ExcludeRegistryKeys>
  <Key>Microsoft\\Windows\\CurrentVersion\\Run\\OneDrive</Key>
  <Key>Microsoft\\Windows\\CurrentVersion\\Run\\SecurityHealth</Key>
</ExcludeRegistryKeys>
```

#### CUSTOM-PERS-002: Scheduled Tasks

**Legitimate Task Patterns:**

```xml
<AllowedTaskPatterns>
  <Pattern>Microsoft\\Windows\\.*</Pattern>
  <Pattern>OneDrive Standalone Update Task</Pattern>
  <Pattern>GoogleUpdateTaskMachine</Pattern>
</AllowedTaskPatterns>
```

**Time-Based Rules:**

```xml
<!-- Maintenance window exclusions -->
<MaintenanceWindow>
  <StartTime>01:00</StartTime>
  <EndTime>05:00</EndTime>
  <DaysOfWeek>Sunday</DaysOfWeek>
</MaintenanceWindow>
```

### Data Exfiltration Detection Rules

#### CUSTOM-EXFIL-001: Large File Transfers

**Business Process Exclusions:**

| Process | Data Volume | Time Window |
|---------|-------------|-------------|
| Backup transfers | Unlimited | Maintenance window |
| File sync | 10GB+ | Business hours |
| Database export | 5GB+ | Approved windows |

**Threshold Tuning:**

```xml
<!-- Environment-specific thresholds -->
<Thresholds>
  <SmallEnv>100MB</SmallEnv>
  <MediumEnv>500MB</MediumEnv>
  <LargeEnv>1GB</LargeEnv>
</Thresholds>
```

**Whitelisted Destinations:**

```xml
<AllowedDestinations>
  <IP>10.100.1.50</IP>  <!-- Backup server -->
  <IP>10.100.1.51</IP>  <!-- File server -->
  <Domain>onedrive.com</Domain>
</AllowedDestinations>
```

#### CUSTOM-EXFIL-002: Cloud Storage Uploads

**Authorized Cloud Services:**

```xml
<AllowedCloudServices>
  <Service>OneDrive for Business</Service>
  <Service>SharePoint Online</Service>
  <Service>Teams Files</Service>
</AllowedCloudServices>
```

**User Role Exceptions:**

| Role | Upload Limit | Justification |
|------|-------------|---------------|
| Data Analyst | 100GB/day | Business requirement |
| Marketing | 50GB/day | Campaign materials |
| Executives | 10GB/day | Document sharing |

### Living off the Land Detection Rules

#### CUSTOM-LOTL-001: Malicious PowerShell

**Authorized Script Signing:**

```xml
<!-- Allow signed scripts -->
<AllowSignedScripts>true</AllowSignedScripts>
<AllowedSigners>
  <Signer>Company IT Department</Signer>
  <Signer>Microsoft Corporation</Signer>
</AllowedSigners>
```

**Execution Policy Exclusions:**

```xml
<!-- Allow specific execution contexts -->
<AllowedContexts>
  <Context>RemoteSigned</Context>
  <Context>AllSigned</Context>
</AllowedContexts>
```

#### CUSTOM-LOTL-002: WMI Execution

**Legitimate Use Cases:**

| Use Case | Process | Action |
|----------|---------|---------|
| System inventory | wmic.exe | MONITOR |
| Patch management | wmic.exe | MONITOR |
| License management | wmic.exe | MONITOR |

**Time-Based Monitoring:**

```xml
<!-- Alert only during suspicious hours -->
<AlertHours>18:00-08:00</AlertHours>
```

### Privilege Escalation Detection Rules

#### CUSTOM-PRIV-001: UAC Bypass

**Legitimate Administrative Actions:**

```xml
<AllowedActions>
  <Action>Software installation</Action>
  <Action>System configuration</Action>
  <Action>Driver installation</Action>
</AllowedActions>
```

**Admin Exclusions:**

```xml
<ExcludeUsers>
  <User>Built-in Administrator</User>
  <User>Domain Admins</User>
  <User>Enterprise Admins</User>
</ExcludeUsers>
```

#### CUSTOM-PRIV-002: Token Impersonation

**Development/Testing Exclusions:**

```xml
<DevelopmentSystems>
  <System>DEV-*</System>
  <System>TEST-*</System>
  <System>LAB-*</System>
</DevelopmentSystems>
```

### Initial Access Detection Rules

#### CUSTOM-INIT-001: Phishing Links

**Security Testing Exceptions:**

```xml
<SecurityTesting>
  <User>Phishing_Test_Users</User>
  <Domain>security.company.com</Domain>
  <Schedule>Monthly</Schedule>
</SecurityTesting>
```

**Browser Policy Integration:**

```xml
<!-- Allow security tools to test -->
<AllowedBrowserExtensions>
  <Extension>PhishDetector</Extension>
  <Extension>SecurityScanner</Extension>
</AllowedBrowserExtensions>
```

#### CUSTOM-INIT-002: Malicious Attachments

**IT Operations Exceptions:**

```xml
<AllowedFileTypes>
  <Type>Executables for patching</Type>
  <Type>Script deployment packages</Type>
  <Type>Configuration files</Type>
</AllowedFileTypes>
```

## Post-Deployment Tuning

### First 30 Days: Intensive Monitoring

**Week 1:**
- Deploy to 10% of environment (pilot group)
- Review all alerts manually
- Document false positives
- Adjust thresholds

**Week 2:**
- Expand to 25% of environment
- Implement initial exclusions
- Refine risk scoring
- Update suppression rules

**Week 3:**
- Deploy to 50% of environment
- Automate alert triage
- Implement exception management
- Train SOC team

**Week 4:**
- Full deployment
- Establish baseline metrics
- Document lessons learned
- Plan optimization sprints

### Ongoing Optimization

**Monthly Reviews:**

1. **False Positive Analysis**
   - Identify top alert sources
   - Implement additional exclusions
   - Adjust thresholds

2. **Threat Detection Effectiveness**
   - Review detection coverage
   - Identify gaps
   - Deploy new rules

3. **Performance Optimization**
   - Review query performance
   - Optimize resource usage
   - Scale as needed

**Quarterly Assessments:**

1. **Rule Effectiveness Review**
   - Detection rate analysis
   - False positive trends
   - Business impact assessment

2. **Environment Changes**
   - New applications
   - Infrastructure changes
   - Policy updates

3. **Threat Landscape Updates**
   - New attack techniques
   - Emerging threats
   - TTP evolution

## Tuning Metrics

### Key Performance Indicators

| Metric | Target | Measurement |
|--------|--------|-------------|
| False Positive Rate | < 5% | FP / Total Alerts |
| Detection Rate | > 90% | Detected / Total Incidents |
| Mean Time to Detect | < 5 min | First detection to alert |
| Alert Volume | < 200/day | Total alerts per day |
| Coverage | > 95% | MITRE techniques covered |

### Tuning Effectiveness Measures

1. **Alert Reduction**
   - Baseline: Week 1 alert count
   - Current: Weekly alert count
   - Target: 50% reduction by Week 4

2. **Signal-to-Noise Ratio**
   - True positives / Total alerts
   - Target: > 95% signal

3. **Response Time**
   - Alert to investigation time
   - Target: < 15 minutes

## Exception Management

### Creating Exceptions

**Step 1: Document Exception Request**
- User/System name
- Business justification
- Duration (temporary or permanent)
- Risk acceptance

**Step 2: Implement Exception**
- Add to exclusion list
- Document in CMDB
- Set expiration date
- Notify stakeholders

**Step 3: Monitor Exception**
- Track alert suppression
- Review for abuse
- Expire when no longer needed

### Exception Governance

**Approval Matrix:**

| Exception Type | Approver | Validity Period |
|----------------|----------|-----------------|
| Individual user | Team Lead | 30 days |
| System/Process | IT Manager | 90 days |
| Department | Dept Head | 180 days |
| Enterprise-wide | CISO | 365 days |

## Advanced Tuning Techniques

### Machine Learning Integration

**Anomaly Detection:**
- Establish behavioral baselines
- Identify deviations
- Auto-tune thresholds

**Pattern Recognition:**
- Identify attack patterns
- Correlate alerts
- Reduce false positives

### Threat Intelligence Integration

**IOC-Based Tuning:**
- Incorporate threat feeds
- Adjust sensitivity
- Prioritize known threats

**Campaign Tracking:**
- Identify coordinated attacks
- Adjust detection levels
- Share intelligence

## Communication and Training

### Stakeholder Communication

**Weekly Reports:**
- Alert summary
- False positive trends
- Exception requests
- Tuning recommendations

**Monthly Reviews:**
- Effectiveness metrics
- Environment changes
- Risk assessments
- Roadmap updates

### Team Training

**SOC Analyst Training:**
- Rule behavior and tuning
- Investigation procedures
- Exception management
- Reporting requirements

**User Training:**
- Security awareness
- Phishing recognition
- Incident reporting
- Policy compliance

## Best Practices

### Do's

- ✅ Start with conservative thresholds
- ✅ Document all changes
- ✅ Test in non-production first
- ✅ Monitor continuously
- ✅ Involve stakeholders
- ✅ Automate where possible

### Don'ts

- ❌ Never disable alerts without documentation
- ❌ Avoid blanket exclusions
- ❌ Don't ignore alert trends
- ❌ Don't skip testing
- ❌ Maintain unsupported rules

## Tool Integration

### SIEM Integration

**Microsoft Sentinel:**
- Custom analytics rules
- Workbook dashboards
- Automation playbooks
- Threat intelligence

**Splunk:**
- Custom searches
- Dashboard panels
- Alert actions
- Machine learning

### Automation Platforms

**Power Automate:**
- Alert workflows
- Exception requests
- Reporting automation
- Notification systems

**ServiceNow:**
- Incident creation
- Change management
- Exception tracking
- Asset management

## Support and Resources

### Documentation

- [Microsoft Defender XDR Documentation](https://learn.microsoft.com/defender-xdr/)
- [KQL Reference](https://learn.microsoft.com/kusto/query/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

### Community

- [Microsoft Security Community](https://techcommunity.microsoft.com/security)
- [GitHub Repository](https://github.com/org/defender-custom-detections)
- [User Forums](https://techcommunity.microsoft.com/)

### Support Channels

| Issue Type | Channel | Response Time |
|------------|---------|---------------|
| Critical Issues | PagerDuty | < 1 hour |
| Rule Tuning | Email | < 24 hours |
| Documentation | GitHub | < 48 hours |
| General Support | Forums | < 72 hours |

---

**Last Updated:** 2026-04-27  
**Version:** 1.0.0  
**Next Review:** 2026-07-27