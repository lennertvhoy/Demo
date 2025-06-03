# Risk Assessment Workshop

## Objective
Learn how to conduct a comprehensive security risk assessment and develop risk mitigation strategies.

## Prerequisites
- Understanding of basic cybersecurity concepts
- Familiarity with the CIA triad
- Basic knowledge of threats and vulnerabilities

## Lab Overview
In this workshop, you will:
1. Identify assets and their value
2. Identify threats and vulnerabilities
3. Calculate risk levels
4. Develop risk mitigation strategies
5. Create a risk assessment report

## Part 1: Asset Identification and Valuation

### Exercise 1.1: Asset Inventory
Create an inventory for a fictional small business (e-commerce company):

| Asset Category | Asset | Description | Value (1-5) | Criticality |
|----------------|-------|-------------|-------------|-------------|
| Data | Customer Database | Personal info, payment data | 5 | Critical |
| Hardware | Web Server | Hosts e-commerce platform | 4 | High |
| Software | E-commerce Platform | Online store application | 4 | High |
| Data | Product Inventory | Product listings and prices | 3 | Medium |
| Hardware | Employee Workstations | 10 computers | 2 | Low |

### Exercise 1.2: Asset Valuation Criteria
Rate assets based on:
- **Confidentiality Impact**: What if this information is disclosed?
- **Integrity Impact**: What if this data is modified?
- **Availability Impact**: What if this asset is unavailable?
- **Business Impact**: Revenue loss, reputation damage, legal consequences

## Part 2: Threat Identification

### Exercise 2.1: Threat Modeling
Identify potential threats for each asset:

```
Threat Categories:
1. Natural Disasters (floods, earthquakes, fire)
2. Human Threats
   - Malicious (hackers, insiders, competitors)
   - Accidental (employee errors, misconfigurations)
3. Environmental (power failures, cooling failures)
4. Technical (hardware failures, software bugs)
```

### Exercise 2.2: Threat Mapping
Complete the threat mapping exercise:

| Asset | Potential Threats | Threat Actor | Likelihood (1-5) |
|-------|------------------|--------------|------------------|
| Customer Database | SQL Injection | External Hacker | 4 |
| Customer Database | Data Breach | Malicious Insider | 2 |
| Web Server | DDoS Attack | Competitor/Hacker | 3 |
| E-commerce Platform | Zero-day Exploit | Advanced Threat | 2 |

## Part 3: Vulnerability Assessment

### Exercise 3.1: Vulnerability Identification
Identify vulnerabilities that could be exploited:

```
Common Vulnerabilities:
- Unpatched systems
- Weak passwords
- Misconfigured firewalls
- Lack of encryption
- No backup procedures
- Insufficient access controls
- Missing security awareness training
```

### Exercise 3.2: Vulnerability Analysis
Create a vulnerability assessment matrix:

| Vulnerability | Affected Assets | Severity (1-5) | Ease of Exploitation (1-5) |
|--------------|-----------------|----------------|---------------------------|
| Unpatched Web Server | Web Server, E-commerce Platform | 4 | 3 |
| Weak Admin Passwords | All Systems | 5 | 4 |
| No Data Encryption | Customer Database | 5 | 2 |
| No Backup System | All Data Assets | 4 | N/A |

## Part 4: Risk Calculation

### Exercise 4.1: Risk Formula
Calculate risk using the formula:
```
Risk = Likelihood × Impact
```

Where:
- Likelihood: Probability of threat exploiting vulnerability (1-5)
- Impact: Consequence if the threat occurs (1-5)
- Risk Score: 1-25 (Low: 1-8, Medium: 9-16, High: 17-25)

### Exercise 4.2: Risk Matrix
Complete the risk assessment:

| Threat | Vulnerability | Likelihood | Impact | Risk Score | Risk Level |
|--------|--------------|------------|--------|------------|------------|
| SQL Injection | Unvalidated Input | 4 | 5 | 20 | High |
| DDoS Attack | No DDoS Protection | 3 | 4 | 12 | Medium |
| Data Theft | Weak Encryption | 2 | 5 | 10 | Medium |
| System Failure | No Backups | 2 | 5 | 10 | Medium |

## Part 5: Risk Mitigation Strategies

### Exercise 5.1: Risk Treatment Options
For each identified risk, choose appropriate treatment:

1. **Risk Avoidance**: Eliminate the risk by removing the asset or activity
2. **Risk Reduction**: Implement controls to reduce likelihood or impact
3. **Risk Transfer**: Insurance or outsourcing
4. **Risk Acceptance**: Accept the risk if cost of mitigation exceeds potential loss

### Exercise 5.2: Control Implementation Plan
Develop mitigation strategies:

| Risk | Treatment | Proposed Controls | Cost | Priority |
|------|-----------|------------------|------|----------|
| SQL Injection (High) | Reduction | Input validation, WAF, code review | $5,000 | 1 |
| Weak Passwords (High) | Reduction | Password policy, MFA | $2,000 | 2 |
| No Backups (Medium) | Reduction | Automated backup system | $3,000 | 3 |
| DDoS Attack (Medium) | Transfer | DDoS protection service | $500/month | 4 |

## Part 6: Risk Assessment Report

### Exercise 6.1: Executive Summary Template
Write an executive summary including:
```
1. Assessment Scope and Objectives
2. Methodology Used
3. Key Findings
   - Number of high/medium/low risks identified
   - Most critical vulnerabilities
   - Immediate action items
4. Recommendations
5. Budget Requirements
```

### Exercise 6.2: Detailed Risk Register
Create a comprehensive risk register:

```
Risk ID: R001
Risk Title: Customer Database SQL Injection Vulnerability
Category: Technical
Description: The customer database is vulnerable to SQL injection attacks due to 
             lack of input validation in the web application.
Current Controls: None
Likelihood: 4/5
Impact: 5/5
Risk Score: 20 (High)
Recommended Controls:
- Implement parameterized queries
- Deploy Web Application Firewall
- Regular security code reviews
Residual Risk After Controls: 6 (Low)
Owner: IT Security Manager
Due Date: Within 30 days
```

## Part 7: Continuous Risk Management

### Exercise 7.1: Risk Monitoring Plan
Develop a monitoring strategy:
1. **Monthly**: Review and update risk register
2. **Quarterly**: Reassess high-priority risks
3. **Annually**: Complete risk assessment
4. **Trigger-based**: Assess new risks when:
   - New systems are deployed
   - Major changes occur
   - Security incidents happen

### Exercise 7.2: Key Risk Indicators (KRIs)
Define metrics to monitor risk levels:
- Number of security patches pending
- Days since last security training
- Number of failed login attempts
- Percentage of systems with updated antivirus
- Time to detect security incidents

## Lab Exercises

### Scenario 1: New Threat Assessment
A new ransomware variant is targeting businesses in your industry.
1. Assess the threat level for your organization
2. Identify vulnerable assets
3. Calculate the risk score
4. Propose mitigation strategies

### Scenario 2: Third-Party Risk
Your company is considering using a cloud service provider.
1. Identify new risks introduced
2. Assess data security risks
3. Evaluate vendor security controls
4. Determine risk acceptance criteria

## Assessment Questions

1. What is the difference between a threat and a vulnerability?
2. Why is asset valuation important in risk assessment?
3. Explain when risk acceptance might be appropriate.
4. How do you determine the priority order for implementing controls?
5. What factors influence the likelihood rating of a threat?

## Best Practices

### Risk Assessment Tips:
1. Involve stakeholders from all departments
2. Use standardized risk assessment frameworks (NIST, ISO 27005)
3. Document all assumptions and decisions
4. Regular reviews and updates
5. Consider both technical and non-technical risks

### Common Pitfalls to Avoid:
- Focusing only on technical risks
- Underestimating insider threats
- Ignoring low-probability, high-impact events
- Not considering cascading failures
- Failing to update assessments regularly

## Conclusion
This workshop has covered the fundamentals of risk assessment:
- Asset identification and valuation
- Threat and vulnerability analysis
- Risk calculation and prioritization
- Mitigation strategy development
- Continuous risk management

Remember: Risk assessment is an ongoing process, not a one-time activity. Regular updates ensure your security posture remains aligned with the evolving threat landscape.

## Additional Resources
- NIST Risk Management Framework
- ISO 27005 Information Security Risk Management
- FAIR (Factor Analysis of Information Risk) Model
- OCTAVE (Operationally Critical Threat, Asset, and Vulnerability Evaluation) 