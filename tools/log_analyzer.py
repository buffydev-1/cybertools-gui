import re
from collections import defaultdict
from datetime import datetime, timedelta

NGINX_COMMON_RE = re.compile(r'(?P<ip>\S+) - (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<req>[^"]+)" (?P<status>\d{3}) (?P<size>\d+|-)')

def analyze_logs(path, window_minutes=5, brute_thresh=10):
    results = {
        'total_lines': 0,
        'suspicious_ips': {},
        'status_counts': defaultdict(int),
    }
    failed_login_patterns = [
        re.compile(r'Failed password'),
        re.compile(r'authentication failure'),
        re.compile(r'Invalid user'),
        re.compile(r'401'),
    ]
    ip_timestamps = defaultdict(list)

    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                results['total_lines'] += 1
                m = NGINX_COMMON_RE.search(line)
                if m:
                    status = int(m.group('status'))
                    ip = m.group('ip')
                    results['status_counts'][status] += 1
                    time_raw = m.group('time')
                    try:
                        dt = datetime.strptime(time_raw.split()[0], "%d/%b/%Y:%H:%M:%S")
                        ip_timestamps[ip].append(dt)
                    except Exception:
                        pass
                for p in failed_login_patterns:
                    if p.search(line):
                        ip_search = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', line)
                        ip = ip_search.group(1) if ip_search else 'unknown'
                        results['suspicious_ips'].setdefault(ip, 0)
                        results['suspicious_ips'][ip] += 1
    except FileNotFoundError:
        raise

    brute_candidates = {}
    for ip, times in ip_timestamps.items():
        times.sort()
        left = 0
        for right in range(len(times)):
            while times[right] - times[left] > timedelta(minutes=window_minutes):
                left += 1
            cnt = right - left + 1
            if cnt >= brute_thresh:
                brute_candidates[ip] = max(brute_candidates.get(ip, 0), cnt)

    return {'summary': results, 'brute_candidates': brute_candidates}
