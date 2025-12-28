# Comprehensive Exploitability Analysis Test Plan

## Test Application Overview

**Application:** vuln-app (Exploitability Test Application)
**Namespace:** exploit-test
**Purpose:** Validate end-to-end exploitability analysis across SAST, SCA, and Image scanners

## Vulnerability Categories

### 1. REACHABLE Code Vulnerabilities (SAST) ✅

| Endpoint | Vulnerability Type | Severity | Attack Vector | Expected Result |
|----------|-------------------|----------|---------------|-----------------|
| `POST /api/login` | SQL Injection | HIGH | Direct user input in SQL query | ✅ Should be flagged as EXPLOITABLE |
| `GET /api/search` | Reflected XSS | MEDIUM | Unescaped user input in HTML | ✅ Should be flagged as EXPLOITABLE |
| `POST /api/exec` | Command Injection | CRITICAL | shell=True with user input | ✅ Should be flagged as EXPLOITABLE |
| `POST /api/config` | YAML Deserialization | CRITICAL | yaml.load() without safe loader | ✅ Should be flagged as EXPLOITABLE |
| `POST /api/session` | Pickle Deserialization | CRITICAL | pickle.loads() with user data | ✅ Should be flagged as EXPLOITABLE |
| `GET /api/proxy` | SSRF | HIGH | Unvalidated URL requests | ✅ Should be flagged as EXPLOITABLE |

**Total REACHABLE SAST Vulnerabilities:** 6

### 2. NON-REACHABLE Code Vulnerabilities (SAST) ❌

| Function | Vulnerability Type | Severity | Why Not Reachable | Expected Result |
|----------|-------------------|----------|-------------------|-----------------|
| `admin_backdoor_unreachable()` | Path Traversal | HIGH | No route calls this function | ❌ Should NOT be flagged as exploitable |
| `debug_shell_unreachable()` | Command Injection | CRITICAL | Internal debug function, never called | ❌ Should NOT be flagged as exploitable |
| `decrypt_secret_unreachable()` | Weak Crypto | MEDIUM | Helper function, never used | ❌ Should NOT be flagged as exploitable |

**Total NON-REACHABLE SAST Vulnerabilities:** 3

### 3. REACHABLE Dependency Vulnerabilities (SCA) ✅

| Endpoint | Package | CVE | Severity | Why Reachable | Expected Result |
|----------|---------|-----|----------|---------------|-----------------|
| `POST /api/jwt-decode` | PyJWT==1.7.1 | CVE-2022-29217 | HIGH | Function uses jwt.decode() | ✅ Should be flagged as EXPLOITABLE |
| `POST /api/ssh-connect` | paramiko==2.7.2 | CVE-2022-24302 | MEDIUM | Function uses paramiko.SSHClient() | ✅ Should be flagged as EXPLOITABLE |
| `POST /api/config` | PyYAML==5.3.1 | CVE-2020-14343 | CRITICAL | Function uses yaml.load() | ✅ Should be flagged as EXPLOITABLE |
| `POST /api/login` | Flask==2.0.1 | CVE-2023-30861 | MEDIUM | App uses Flask request handling | ✅ Should be flagged as EXPLOITABLE |
| `GET /api/proxy` | requests==2.25.1 | CVE-2023-32681 | MEDIUM | Function uses requests.get() | ✅ Should be flagged as EXPLOITABLE |

**Total REACHABLE SCA Vulnerabilities:** 5+

### 4. NON-REACHABLE Dependency Vulnerabilities (SCA) ❌

| Function | Package | CVE | Why Not Reachable | Expected Result |
|----------|---------|-----|-------------------|-----------------|
| `unused_crypto_function()` | cryptography==3.3.2 | CVE-2023-23931 | Function never called | ❌ Should NOT be flagged as exploitable |
| `unused_yaml_parser()` | PyYAML==5.3.1 | CVE-2020-14343 | Duplicate unused function | ❌ Should NOT be flagged as exploitable |

**Total NON-REACHABLE SCA Vulnerabilities:** 2

### 5. Image Vulnerabilities (CVEs in Base Image) 🔍

| Package | Type | Expected Severity | Attack Chain Potential |
|---------|------|------------------|------------------------|
| curl | System | MEDIUM-HIGH | Can be used for data exfiltration if RCE exists |
| wget | System | MEDIUM | Can be used for downloading malicious payloads |
| vim | System | LOW-MEDIUM | Can be used for privilege escalation if exploited |
| openssh-client | System | MEDIUM | Can be used for lateral movement |
| python3.9 | Runtime | MEDIUM-HIGH | Python interpreter vulnerabilities |

**Expected Attack Chains:**
1. **SAST Command Injection → Image curl CVE → Data Exfiltration**
   - Initial Access: POST /api/exec (Command Injection)
   - Privilege Escalation: Container runs as root + privileged mode
   - Data Exfiltration: Use curl (with CVEs) to send data

2. **SAST SSRF → Image wget CVE → Malware Download**
   - Initial Access: GET /api/proxy (SSRF to IMDS)
   - Lateral Movement: Steal AWS credentials
   - Persistence: Use wget (with CVEs) to download backdoor

3. **SCA PyYAML → Image vim CVE → Container Escape**
   - Initial Access: POST /api/config (YAML Deserialization RCE)
   - Container Escape: Leverage vim CVEs + SYS_ADMIN capability
   - Host Compromise: Mount /host filesystem

## Container Security Misconfigurations

| Misconfiguration | Risk Level | Impact |
|------------------|------------|--------|
| `runAsUser: 0` (root) | CRITICAL | Full container privileges |
| `privileged: true` | CRITICAL | Kernel access, easy container escape |
| `hostNetwork: true` | HIGH | Access to host network stack |
| `hostPID: true` | HIGH | Can see/kill host processes |
| `capabilities: [SYS_ADMIN, NET_ADMIN, SYS_PTRACE]` | CRITICAL | Linux capabilities abuse |
| Host path mount `/` at `/host` | CRITICAL | Read/write access to host filesystem |
| Exposed secrets in env vars | HIGH | Hardcoded AWS keys, passwords |

## RBAC Misconfigurations

| Permission | Risk Level | Impact |
|------------|------------|--------|
| `secrets: [get, list, delete]` | CRITICAL | Can read all cluster secrets |
| `pods: [create, delete]` | HIGH | Can create malicious pods |
| ClusterRole (not namespaced) | HIGH | Cluster-wide permissions |

## Expected Exploitability Analysis Results

### Summary Metrics

| Metric | Expected Value |
|--------|---------------|
| Total Vulnerabilities Detected | 14+ (SAST) + 7+ (SCA) + ~50+ (Image) = **70+ total** |
| Reachable/Exploitable | 11 (SAST + SCA reachable) |
| Non-Reachable | 5 (SAST + SCA dead code) |
| Attack Chains Detected | 3-5 multi-step chains |
| Container Escape Paths | 2-3 paths |
| Data Exfiltration Paths | 2-3 paths |
| MITRE ATT&CK Techniques | 10-15 techniques |

### MITRE ATT&CK Mapping (Expected)

| Tactic | Techniques | Count |
|--------|-----------|-------|
| Initial Access | T1190 (Exploit Public-Facing Application) | 1 |
| Execution | T1059 (Command and Scripting Interpreter) | 3 |
| Persistence | T1053 (Scheduled Task/Job) | 1 |
| Privilege Escalation | T1611 (Escape to Host), T1068 (Exploitation for Privilege Escalation) | 2 |
| Defense Evasion | T1070 (Indicator Removal) | 1 |
| Credential Access | T1552 (Unsecured Credentials) | 2 |
| Discovery | T1082 (System Information Discovery) | 1 |
| Lateral Movement | T1021 (Remote Services) | 1 |
| Collection | T1005 (Data from Local System) | 1 |
| Exfiltration | T1041 (Exfiltration Over C2 Channel) | 1 |
| Impact | T1499 (Endpoint Denial of Service) | 1 |

**Total MITRE Techniques:** 15+

## Test Execution Steps

### Phase 1: Deploy and Discover
1. ✅ Deploy vulnerable application
2. ⏳ Wait for ai-spm-agent to discover assets
3. ⏳ Wait for scan-decision-engine to enqueue scans
4. ⏳ Wait for scanner workers to complete scans

### Phase 2: Scan Execution
1. ⏳ Image Scanner: Detect CVEs in base image and packages
2. ⏳ SAST Scanner: Analyze Python code for vulnerabilities
3. ⏳ SCA Scanner: Analyze dependencies and reachability
4. ⏳ OSS Scanner: Validate open source package CVEs

### Phase 3: Exploitability Analysis
1. ⏳ Exploitability Analyzer Service: Process all vulnerabilities
2. ⏳ Cross-scanner correlation: Link SAST + SCA + Image CVEs
3. ⏳ Attack chain detection: Identify multi-step attack paths
4. ⏳ Risk scoring: Calculate multi-dimensional risk scores
5. ⏳ MITRE mapping: Map vulnerabilities to ATT&CK framework

### Phase 4: Validation
1. ⏳ Query `unified_vulnerabilities` table
2. ⏳ Query `sca_exploitability_analysis` table
3. ⏳ Query `sast_exploitability_analysis` table
4. ⏳ Query `image_exploitability_analysis` table
5. ⏳ Validate reachability flags (is_reachable, is_exploitable)
6. ⏳ Validate attack chains in exploitability tables
7. ⏳ Compare expected vs actual results

## Success Criteria

### Core Functionality
- [ ] All REACHABLE vulnerabilities are flagged as exploitable
- [ ] All NON-REACHABLE vulnerabilities are flagged as non-exploitable
- [ ] Reachability analysis accuracy > 90%
- [ ] False positive rate < 10%

### Attack Chain Detection
- [ ] At least 3 multi-step attack chains detected
- [ ] SAST → Image CVE correlation working
- [ ] SCA → Image CVE correlation working
- [ ] Container escape paths identified

### Risk Scoring
- [ ] CRITICAL vulnerabilities have risk_score > 9.0
- [ ] HIGH vulnerabilities have risk_score 7.0-9.0
- [ ] MEDIUM vulnerabilities have risk_score 4.0-7.0
- [ ] Exploitable vulns have higher scores than non-exploitable

### MITRE ATT&CK
- [ ] At least 10 MITRE techniques mapped
- [ ] All major tactics represented (Initial Access, Execution, Privilege Escalation)

### Database Integrity
- [ ] All exploitability tables populated
- [ ] Cross-references between tables valid
- [ ] No orphaned records
- [ ] Timestamps correctly set

## Test Execution Commands

```bash
# 1. Check asset discovery
kubectl get pods -n exploit-test -o json | jq -r '.items[].metadata.name'

# 2. Verify scans were triggered
PGPASSWORD=postgres psql -h localhost -U postgres -d ai_spm \
  -c "SELECT COUNT(*), scanner_type FROM scans WHERE asset_id IN (SELECT id FROM assets WHERE namespace='exploit-test') GROUP BY scanner_type;"

# 3. Check vulnerability detection
PGPASSWORD=postgres psql -h localhost -U postgres -d ai_spm \
  -c "SELECT scanner_type, COUNT(*), AVG(cvss_score) FROM unified_vulnerabilities WHERE asset_id IN (SELECT id FROM assets WHERE namespace='exploit-test') GROUP BY scanner_type;"

# 4. Validate exploitability analysis
PGPASSWORD=postgres psql -h localhost -U postgres -d ai_spm \
  -c "SELECT COUNT(*) as total, COUNT(CASE WHEN is_exploitable THEN 1 END) as exploitable FROM sast_exploitability_analysis WHERE asset_id IN (SELECT id FROM assets WHERE namespace='exploit-test');"

# 5. Check attack chains
PGPASSWORD=postgres psql -h localhost -U postgres -d ai_spm \
  -c "SELECT attack_chain_id, attack_chain_type, risk_score FROM image_exploitability_analysis WHERE attack_chain_detected = true LIMIT 10;"
```

