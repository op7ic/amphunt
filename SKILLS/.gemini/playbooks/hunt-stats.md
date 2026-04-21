# Playbook: Statistical Anomaly Detection

## Objective
Generate environment-wide statistics to identify anomalies and outlier endpoints for prioritized investigation.

## Scripts
- **amp_generic_stats.py** -- Collect and aggregate security metrics

## Commands
```bash
python3 amp_generic_stats.py -c config.txt --csv stats.csv
```

## Metrics
- Vulnerable application counts, network event (NFM) frequency
- File execution/creation/movement counts
- Threat detection/quarantine counts
- Malicious activity detection counts

## Analysis
1. Run stats across environment
2. Find endpoints with counts significantly above peers
3. High threat/network endpoints warrant deep investigation
4. Compare against historical baselines

## Follow-Up Playbooks
- High-threat endpoints -> `playbooks/hunt-timeline.md`
- High network activity -> `playbooks/hunt-network.md`
- Many vulnerabilities -> `playbooks/hunt-vulnerabilities.md`
