"""Read-only Windows authentication event detection from normalized JSON records."""
import argparse
import csv
import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path


def parse_time(value):
    dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if dt.tzinfo is None:
        raise ValueError('Event timestamps must include timezone information')
    return dt.astimezone(timezone.utc)


def detect(events, threshold=5, window_minutes=5):
    """Return findings; input events require time,event_id,account,source_ip,logon_type."""
    if threshold < 1 or window_minutes < 1:
        raise ValueError('threshold and window_minutes must be positive')
    normalized = []
    for event in events:
        if int(event['event_id']) not in (4624, 4625):
            continue
        normalized.append({**event, 'event_id': int(event['event_id']),
                           'logon_type': int(event.get('logon_type') or 0),
                           '_time': parse_time(event['time'])})
    normalized.sort(key=lambda e: e['_time'])
    failures = defaultdict(list)
    successes = []
    findings = []
    window = timedelta(minutes=window_minutes)
    for e in normalized:
        key = (e.get('account', ''), e.get('source_ip', ''))
        if e['event_id'] == 4625:
            failures[key].append(e)
        else:
            successes.append(e)
            if e['logon_type'] == 10:
                findings.append({'rule': 'RDP_LOGON_REVIEW', 'severity': 'medium',
                                 'time': e['time'], 'account': key[0], 'source_ip': key[1],
                                 'details': 'Successful remote interactive logon; verify authorization'})
    # Sliding windows; emit one finding per consecutive failure cluster rather than every overlapping window.
    for key, group in failures.items():
        start = 0
        alerted_through = -1
        for end, e in enumerate(group):
            while group[start]['_time'] < e['_time'] - window:
                start += 1
            if end - start + 1 >= threshold and start > alerted_through:
                findings.append({'rule': 'BRUTE_FORCE_PATTERN', 'severity': 'high',
                                 'time': e['time'], 'account': key[0], 'source_ip': key[1],
                                 'details': f'{end-start+1} failed logons in {window_minutes} minutes'})
                alerted_through = end
    for e in successes:
        key = (e.get('account', ''), e.get('source_ip', ''))
        recent = [f for f in failures[key] if e['_time'] - window <= f['_time'] <= e['_time']]
        if len(recent) >= threshold:
            findings.append({'rule': 'FAILURES_THEN_SUCCESS', 'severity': 'high',
                             'time': e['time'], 'account': key[0], 'source_ip': key[1],
                             'details': f'Successful logon after {len(recent)} recent failed attempts'})
    return sorted(findings, key=lambda f: (f['time'], f['rule']))


def main():
    p = argparse.ArgumentParser(description='SOC authentication detection lab (normalized JSON)')
    p.add_argument('--input', required=True, help='JSON list of normalized authentication events')
    p.add_argument('--output', default='output', help='Output directory')
    p.add_argument('--threshold', type=int, default=5)
    p.add_argument('--window', type=int, default=5, help='Window in minutes')
    args = p.parse_args()
    events = json.loads(Path(args.input).read_text(encoding='utf-8'))
    findings = detect(events, args.threshold, args.window)
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    (out / 'findings.json').write_text(json.dumps(findings, indent=2) + '\n', encoding='utf-8')
    with (out / 'findings.csv').open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['rule', 'severity', 'time', 'account', 'source_ip', 'details'])
        writer.writeheader()
        writer.writerows(findings)
    print(f'Analyzed {len(events)} records; generated {len(findings)} findings in {out}')
    for finding in findings:
        print(f"[{finding['severity'].upper()}] {finding['rule']}: {finding['account']} / {finding['source_ip']}")


if __name__ == '__main__':
    main()
