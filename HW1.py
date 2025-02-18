import re
from collections import Counter, defaultdict
from datetime import datetime

def categorize_log_entries(log_files, output_file):
    failed_pattern = re.compile(r'(?P<timestamp>\w+ \w+ \d+ \d+:\d+:\d+) (?P<domain>\S+) .* Failed password for (invalid user )?(?P<user>\w+) from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+) ssh2')
    
    hacker_attempts = defaultdict(lambda: Counter())
    hacker_time = defaultdict(lambda: defaultdict(list))
    account_attempts = Counter()
    domain_attempts = Counter()
    hacker_count_per_domain = Counter()
    
    for log_file in log_files:
        with open(log_file, 'r') as infile:
            for line in infile:
                if match := failed_pattern.search(line):
                    timestamp_str = match.group("timestamp")
                    domain = match.group("domain")
                    user = match.group("user")
                    ip = match.group("ip")
                    
                    timestamp = datetime.strptime(timestamp_str, "%b %d %Y %H:%M:%S")
                    hacker_attempts[domain][ip] += 1
                    hacker_time[domain][ip].append(timestamp)
                    account_attempts[user] += 1
                    domain_attempts[domain] += 1
    
    hacker_summary = {}
    longest_hacker_per_domain = {}
    most_attempted_hacker_per_domain = {}
    
    for domain, domain_ips in hacker_attempts.items():
        hacker_summary[domain] = {}
        hacker_count_per_domain[domain] = len(domain_ips)
        for ip, attempts in domain_ips.items():
            if attempts > 13:
                all_times = sorted(hacker_time[domain][ip])
                total_duration = (all_times[-1] - all_times[0]).total_seconds() if len(all_times) > 1 else 0
                hours, remainder = divmod(int(total_duration), 3600)
                minutes, seconds = divmod(remainder, 60)
                hacker_summary[domain][ip] = {"attempts": attempts, "duration": f"{hours} Hour {minutes} Minute {seconds} Second"}
        
        if hacker_summary[domain]:
            longest_hacker_per_domain[domain] = max(hacker_summary[domain], key=lambda ip: int(hacker_summary[domain][ip]["duration"].split()[0]) * 3600 + int(hacker_summary[domain][ip]["duration"].split()[2]) * 60 + int(hacker_summary[domain][ip]["duration"].split()[4]), default=None)
            most_attempted_hacker_per_domain[domain] = max(hacker_summary[domain], key=lambda ip: hacker_summary[domain][ip]["attempts"], default=None)
    
    domain_summary = dict(sorted(domain_attempts.items(), key=lambda item: item[1], reverse=True))
    most_targeted_account = max(account_attempts, key=account_attempts.get, default=None)
    total_hackers = sum(hacker_count_per_domain.values())
    
    with open(output_file, 'w', encoding='utf-8') as outfile:
        outfile.write("HACKER ATTEMPTS PER DOMAIN (More than 13 failed attempts per day) sorted by attempts:\n")
        for domain, hackers in hacker_summary.items():
            outfile.write(f"\nDOMAIN: {domain}\n")
            for ip, details in hackers.items():
                outfile.write(f"IP: {ip}, Failed Attempts: {details['attempts']}, Duration: {details['duration']}\n")
            longest_hacker = longest_hacker_per_domain.get(domain, None)
            most_attempted_hacker = most_attempted_hacker_per_domain.get(domain, None)
            if longest_hacker:
                outfile.write(f"Longest hacking attempt in {domain}: {longest_hacker} with {hacker_summary[domain][longest_hacker]['duration']}\n")
            if most_attempted_hacker:
                outfile.write(f"Most failed attempts in {domain}: {most_attempted_hacker} with {hacker_summary[domain][most_attempted_hacker]['attempts']} attempts\n")
        
        outfile.write(f"\nMost targeted account: {most_targeted_account} with {account_attempts[most_targeted_account]} attempts\n")
        outfile.write("\nDOMAINS TARGETED MOST OFTEN:\n")
        for domain, count in domain_summary.items():
            outfile.write(f"Domain: {domain}, Attempts: {count}, Hackers: {hacker_count_per_domain[domain]}\n")
        outfile.write(f"\nTotal Hackers: {total_hackers}\n")
    
    print(f"Categorized log entries saved to {output_file}")
    print("Hacker Summary per Domain:", hacker_summary)
    print("Longest Hacking Attempt per Domain:", longest_hacker_per_domain)
    print("Most Attempted Hacker per Domain:", most_attempted_hacker_per_domain)
    print("Most Targeted Account:", most_targeted_account)
    print("Most Targeted Domains:", domain_attempts)
    print("Total Unique Hackers:", total_hackers)
    print("Hacker Count Per Domain:", hacker_count_per_domain)
    return hacker_summary, longest_hacker_per_domain, most_attempted_hacker_per_domain, most_targeted_account, domain_summary, total_hackers

log_files = ["secure1.log", "secure2.log", "secure3.log", "secure.log"] 
output_file = "categorized_log_entries.log"

hackers, longest_hackers, most_attempted_hackers, most_targeted, domains, total_hackers = categorize_log_entries(log_files, output_file)
