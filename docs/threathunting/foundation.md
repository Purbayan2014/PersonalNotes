# Threat Hunting Fundamentals

## Reactive Security Approach

- Taking action after an attack has occurred.
- Relies on technologies such as IDS, IPS, antivirus, and firewalls.
- Only effective against known threats and vulnerable to unknown or zero-day threats.

### Reactive Indicators of Compromise (IoCs)

- Malware signatures
- Exploits
- Vulnerabilities
- IP addresses

---

## Proactive Security Approach

- Involves continuous monitoring, analysis, and threat hunting.
- Detects and prevents potential threats.
- Identifies and responds to threats in their early stages.
- Focuses on taking action before attacks occur.

### Proactive Indicators of Attack (IoAs)

- Code execution
- Persistence
- Stealth
- Command and control
- Lateral movement

---

# Threat Hunting Team Structure

- **Threat Hunter**
  - Conducts threat hunts.

- **Incident Responder**
  - Responds to threats and security incidents.

- **Malware Analyst**
  - Analyzes malware and develops strategies against sophisticated attacks.

- **Forensic Analyst**
  - Performs DFIR activities to identify attack sources and methodologies.

- **Security Analyst**
  - Monitors threats and gathers cyber threat intelligence.

---

# Skills of a Threat Hunter

## Threat Analysis and Intelligence Competencies

- Understand attacker behaviors and techniques.
- Conduct threat analysis using frameworks such as MITRE ATT&CK.
- Evaluate and interpret threat intelligence sources.

## Network and System Knowledge

- Deep understanding of network protocols and architectures.
- Knowledge of system and application security principles.
- Experience with IDS/IPS, firewalls, and antivirus solutions.

## Analytical Thinking and Problem-Solving

- Analyze complex datasets.
- Identify abnormal behavior and threats.
- Solve problems quickly and effectively.

## Communication and Reporting

- Communicate effectively with technical and non-technical stakeholders.
- Present findings clearly.
- Collaborate with internal and external teams.

### Recommended Certifications

- eCTHP
- GCIH
- CTIA
- CEH
- CISSP

---

# Adversary-Centric Approach

- Focuses on understanding the attacker's perspective.
- Identifies attacker TTPs.
- Helps uncover vulnerabilities and potential attack paths.

## TTPs (Tactics, Techniques, and Procedures)

### Tactics

General objectives attackers aim to achieve.

**Examples:**

- Information Gathering
- Phishing

### Techniques

Specific methods used to achieve tactics.

**Example:**

- Using OSINT for information gathering.

### Procedures

Detailed implementation steps for techniques.

**Example:**

- Using a specific OSINT tool.

## Implementation

- Analyze threat intelligence and historical attacks.
- Use MITRE ATT&CK to categorize TTPs.
- Continuously monitor evolving attacker techniques.

---

# MITRE ATT&CK Framework

**Adversarial Tactics, Techniques, and Common Knowledge**

A comprehensive knowledge base describing adversary behavior.

## Components

### Tactics

High-level attacker objectives.

Examples:

- Initial Access
- Execution
- Persistence

### Techniques

Methods used to achieve tactics.

Examples:

- Phishing
- Remote File Copying

### Sub-techniques

Specific variations of techniques.

Example:

- Email attachments under phishing.

## Implementation

- Use ATT&CK Matrix to anticipate attacker behavior.
- Develop defensive strategies.
- Understand attack stages.
- Predict attackers' next moves.

---

# Case Study: APT Attack

## Scenario

A state-sponsored threat group launches an APT attack to steal sensitive organizational information.

## Tactics

- Phishing for initial access.
- Backdoors for persistence.

## Techniques

- Malicious email attachments.
- Lateral movement.

## Procedures

- Collect information using malware.
- Exfiltrate data to attacker-controlled servers.

## Detection and Response

### TTP Analysis

Determine techniques used.

### MITRE ATT&CK Usage

Identify attack stages.

Examples:

- Phishing detection
- Malware analysis

### Defense Strategies

- User awareness training.
- Malware detection solutions.
- Network monitoring.

---

# Hypothesis-Driven Approach

A systematic process where threat hunters develop and test assumptions.

## Objectives

- Focus investigations.
- Search for evidence of attacks.

## Process

1. Create a hypothesis.
2. Investigate using tools and techniques.
3. Inform and enrich analytics.
4. Discover new patterns and TTPs.

---

## Creating a Hypothesis

Develop assumptions based on:

- Existing data.
- Threat intelligence.
- Potential attacker behavior.

### Benefits

- Enables targeted investigations.
- Prevents random searching.

### Example

Abnormal traffic may indicate malware activity.

---

## Hypothesis Testing

Validate assumptions through:

- Data collection.
- Analysis.
- Conclusions.

### Benefits

- Improves threat hunting accuracy.
- Eliminates false assumptions quickly.

### Example

Analyze traffic logs to determine malicious activity.

---

## Using Analytical Models

Employ mathematical and statistical techniques.

### Benefits

- Analyze large datasets.
- Detect anomalies.
- Support hypothesis validation.

---

# Case Study: Hypothesis-Based Threat Hunting

## Scenario

A company detects unusual network traffic.

## Hypothesis

> The abnormal traffic increase may indicate a DDoS attack.

## Data Collection

- Examine network traffic logs.

## Analysis

- Use machine learning algorithms.
- Learn normal patterns.
- Detect deviations.

## Conclusion

High traffic from specific IP addresses confirms DDoS activity.

## Intervention

- Block malicious IPs.
- Strengthen defenses.

---

# IoC-Based Approach

IoCs help identify attacks and security breaches.

## Indicators Include

- Attacker traces.
- Tools used.
- Artifacts left behind.

---

# Indicator of Compromise (IoC)

Digital evidence indicating a breach.

Examples:

- Malware activity.
- Suspicious files.
- Abnormal traffic.
- Attacker actions.

---

## Types of IoCs

### File-Based

- Malware files.
- Suspicious modifications.

### Network-Based

- Unknown IP connections.
- Abnormal traffic.

### Host-Based

- Registry modifications.
- Log anomalies.

### Email-Based

- Phishing emails.
- Suspicious attachments.

---

# IoC Databases

Repositories storing known IoCs.

## Key Databases

### OpenIOC

Open IoC standard developed by Mandiant.

### STIX

Structured Threat Information Expression.

### TAXII

Protocol for sharing STIX intelligence.

### VirusTotal

Malware analysis platform.

---

## Using IoC Databases

### Integration

Security tools leverage IoC databases.

### Updates and Maintenance

- Continuous updates.
- Addition of emerging threats.

### Analysis and Reporting

- Analyze attacks.
- Produce reports.
- Implement preventive actions.

---

# Case Study: IoC-Based Threat Hunting

## Scenario

Suspicious activity is observed.

### Indicators

- Network anomalies.
- File modifications.

## IoC Identification

- Analyze logs and traffic.
- Identify malicious IP addresses.

## Database Validation

- Check OpenIOC.
- Check STIX.
- Analyze samples using VirusTotal.

## Response

- Block malicious connections.
- Remove malware.
- Remediate systems.
- Enhance defenses.

---

# Threat Hunting Life Cycle

## 1. Preparation and Planning

### Identifying Resources and Objectives

#### Definition

Determine scope, objectives, systems, and data.

#### Importance

Improves effectiveness.

#### Example

Focus on a specific department.

---

### Selecting Tools and Methods

#### Definition

Choose hunting technologies.

#### Importance

Improves detection capability.

#### Examples

- SIEM
- Network monitoring tools
- Analytical software

---

## 2. Data Collection and Analysis

### Identify and Integrate Data Sources

#### Definition

Gather relevant datasets.

#### Importance

Enables comprehensive analysis.

#### Examples

- System logs
- Network traffic
- User activity
- Threat intelligence

---

### Data Analysis

#### Definition

Analyze collected data.

#### Importance

Supports early detection.

#### Techniques

- Machine learning
- Analytical models

---

## 3. Threat Hunting Process

### Active Threat Hunting Techniques

#### Definition

Techniques used to uncover attackers.

#### Importance

Identify active threats.

#### Examples

- Anomaly detection
- Lateral movement analysis
- User behavior analytics

---

### Continuous Monitoring

#### Definition

Monitor systems continuously.

#### Importance

Enables rapid response.

#### Examples

- SIEM
- EDR

---

## 4. Findings and Reporting

### Documentation

#### Definition

Record findings.

#### Importance

Supports future investigations.

#### Examples

- Threat reports
- Event details
- Analysis results

---

### Reporting

#### Definition

Communicate findings.

#### Importance

Ensures action.

#### Recipients

- Management
- Internal teams
- External stakeholders

---

## 5. Remediation and Optimization

### Taking Action

#### Definition

Respond to identified threats.

#### Importance

Reduce impact.

#### Examples

- Patch vulnerabilities.
- Clean compromised systems.
- Improve controls.

---

### Continuous Improvement

#### Definition

Enhance methodologies over time.

#### Importance

Strengthen future defenses.

#### Examples

- Collect feedback.
- Evaluate performance.
- Adapt to emerging threats.