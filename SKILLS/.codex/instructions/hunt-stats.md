# Hunt: Statistical Anomaly Detection

## Objective
Generate comprehensive environment-wide statistics to identify anomalies and outlier endpoints. Use as a first-pass triage tool to understand security posture.

## Scripts
- **amp_generic_stats.py** -- Collect and aggregate endpoint security metrics

## Commands
```bash
python3 amp_generic_stats.py -c config.txt --csv stats.csv
```

## Metrics Collected
- Vulnerable application counts per endpoint
- Network events (NFM) frequency
- File execution, creation, and movement counts
- Threat detection and quarantine counts
- Malicious activity detection counts

## Analysis Approach
1. Run stats collection across the environment
2. Identify endpoints with significantly higher counts than peers
3. Endpoints with many threat detections or network events warrant deeper investigation
4. Compare against historical baselines if available

## When to Use
- Starting a new threat hunting engagement
- Regular security posture assessments
- Identifying priority investigation targets
- Executive-level security reporting

## Follow-Up
- High-threat endpoints -> `instructions/hunt-timeline.md`
- High network activity -> `instructions/hunt-network.md`
- Many vulnerabilities -> `instructions/hunt-vulnerabilities.md`
