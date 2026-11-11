# Security Scoring & Coverage Algorithm

## 1. Grading Scale (0–100)

| Score Range | Letter Grade | Security Posture |
|---|---|---|
| **95–100** | **A+** | Excellent |
| **90–94** | **A** | Very strong |
| **85–89** | **B+** | Good |
| **80–84** | **B** | Above average |
| **75–79** | **C+** | Moderate |
| **70–74** | **C** | Needs improvement |
| **60–69** | **D** | Weak |
| **0–59** | **F** | Poor |

*Note: If a scan is cancelled or times out with less than 50% module coverage, an asterisk (`*`) is appended to the grade (e.g., `A+*`) and labeled `(Partial Coverage)` so incomplete scans are never mistaken for full assessments.*

---

## 2. Calculation Formula

Scores begin at **100.0** and deduct points per unique root cause:

1. **Root-Cause Deduplication**:
   - All unresolved findings are grouped by `rootCauseKey` (for example, `HEADER_MISSING_CSP` or `SQLI_ERROR_BASED_id`).
   - A missing header across 15 URLs is penalized once as a single root cause, multiplied by a bounded exposure factor:
     $$\text{ExposureMultiplier} = \min(1.25,\; 1.0 + 0.05 \times (\text{UniqueAffectedURLs} - 1))$$

2. **Base Severity Weights**:
   - **Critical**: `28.0` points
   - **High**: `16.0` points
   - **Medium**: `7.5` points
   - **Low**: `2.5` points
   - **Informational**: `0.0` points

3. **Verification Status Multiplier**:
   - **Verified**: `1.0x`
   - **Suspected**: `0.55x`
   - **Needs Manual Review**: `0.25x`
   - **Informational / Incomplete**: `0.0x`

4. **Confidence Multiplier**:
   - **High**: `1.0x`
   - **Medium**: `0.75x`
   - **Low**: `0.45x`

5. **Critical Failure Cap**:
   - If one or more unresolved **Verified Critical** vulnerabilities exist, the final overall score is capped at **69 (Grade D)**.

6. **Independent Scan Coverage Percentage**:
   $$\text{Coverage \%} = \frac{\text{Completed Modules}}{\text{Configured Modules}} \times 100$$
   Skipped, timed-out, or cancelled modules emit an explicit `Incomplete` status entry and are never treated as passing.
