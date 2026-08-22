# triage - scoring rubric
##purpose
This rubric defines how security findings are scored and prioritized.

The scoring system produces three main results

1 Severity
2 Priority
3 Confidence

The system also generates a short human-readable reason explaining why a finding received its priority
# 1. Severity

Severity represents the potential technical impact of the vulnerability.

## Severity Inputs

Each factor is scored from 1 to 5.

### Impact

How much damage could occur if the vulnerability is successfully exploited?

| Score | Meaning |
|---|---|
| 1 | Minimal impact |
| 2 | Limited impact |
| 3 | Moderate impact |
| 4 | Major impact |
| 5 | Critical impact |

### Exploitability

How easily can the vulnerability be exploited?

| Score | Meaning |
|---|---|
| 1 | Very difficult |
| 2 | Difficult |
| 3 | Moderately easy |
| 4 | Easy |
| 5 | Very easy |

### Exposure

How accessible is the vulnerable system?

| Score | Meaning |
|---|---|
| 1 | Highly restricted/internal |
| 2 | Internal |
| 3 | Limited external exposure |
| 4 | Internet-facing |
| 5 | Publicly exposed/highly accessible |

### Privilege Requirement

How much privilege does an attacker need?

| Score | Meaning |
|---|---|
| 1 | High privileges required |
| 2 | Some privileges required |
| 3 | Low privileges required |
| 4 | Minimal privileges required |
| 5 | No privileges required |

## Severity Calculation

The severity score is calculated using:

```text
Severity Score =
(Impact × 2)
+ (Exploitability × 2)
+ Exposure
+ Privilege Requirement

---

# 2. Priority

Priority represents how urgently developers should fix the finding.

Priority considers both technical severity and operational context.

## Priority Inputs

### Severity Weight

| Severity | Weight |
|---|---:|
| Critical | 5 |
| High | 4 |
| Medium | 3 |
| Low | 2 |
| Informational | 1 |

### Exposure

Score from 1–4 based on accessibility.

### Asset Criticality

How important is the affected asset?

| Score | Meaning |
|---|---|
| 1 | Low importance |
| 2 | Normal |
| 3 | Important |
| 4 | Critical |

### Active Exploitation

How strong is the evidence that attackers are exploiting the vulnerability?

| Score | Meaning |
|---|---|
| 1 | No known exploitation |
| 2 | Suspicious/weak evidence |
| 3 | Credible threat activity |
| 4 | Confirmed exploitation |

## Priority Formula

```text
Priority Score =
Severity Weight
+ Exposure
+ Asset Criticality
+ Active Exploitation
