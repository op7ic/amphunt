# Hunt: Statistical Anomaly Detection

## Description
Generate comprehensive environment-wide statistics to identify anomalies and outliers. Use as a first-pass triage tool to understand the security posture and spot endpoints behaving differently from the norm.

## Scripts
- **amp_generic_stats.py** - Collect and aggregate endpoint security metrics

## Usage
```bash
# Full statistics collection
python3 amp_generic_stats.py -c config.txt

# Export for trending/comparison
python3 amp_generic_stats.py -c config.txt --csv stats.csv
```

## Metrics Collected
- Vulnerable application counts per endpoint
- Network events (NFM) frequency
- File execution counts
- File creation counts
- File movement counts
- Threat detection counts
- Quarantine action counts
- Malicious activity detection counts

## Analysis Approach
1. Run stats collection across the environment
2. Look for endpoints with significantly higher counts than peers
3. Endpoints with many threat detections or network events warrant deeper investigation
4. Compare current stats against historical baselines if available

## When to Use
- Starting a new threat hunting engagement
- Regular security posture assessments
- Identifying endpoints that need priority investigation
- Building baselines for anomaly detection
- Executive-level security reporting

## Follow-Up Skills
- If high-threat endpoints found -> `hunt-timeline` for deep-dive
- If high network activity -> `hunt-network` for connection analysis
- If many vulnerabilities -> `hunt-vulnerabilities` for CVE details
