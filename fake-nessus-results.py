import csv
import random

hosts = ['webserver', 'dbserver', 'fileserver', 'appserver', 'mailserver']
protocols = ['tcp', 'udp']
plugin_names = ['HTTP Server Detection', 'MySQL Version Detection', 'SMB Vulnerability', 'Application Version', 'SMTP Open Relay', 'FTP Weak Password', 'SSH Weak Cipher']
cves = ['CVE-2022-1234', 'CVE-2021-2345', 'CVE-2020-3456', 'CVE-2019-4567', 'CVE-2018-5678', '']

# Correct score ranges to map to severity categories (upper bound exclusive)
severity_mapping = [(0, 4, 'Low'), (4, 6, 'Medium'), (6, 9, 'High'), (9, 10.1, 'Critical')]

def map_score_to_severity(score):
    for lower, upper, sev in severity_mapping:
        if lower <= score < upper:
            return sev
    return 'Low'

with open('fake_nessus_scan.csv', 'w', newline='') as csvfile:
    fieldnames = ['Host','IP','Port','Protocol','Severity','Score','Plugin ID','Plugin Name','Description','Solution','CVEs']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

    writer.writeheader()

    for i in range(100):
        host = random.choice(hosts) + str(random.randint(1,20))
        ip = f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"
        port = random.choice([21,22,25,53,80,110,143,443,3306,3389,8080,445])
        protocol = random.choice(protocols)
        score = round(random.uniform(0,10), 1)  # Random float score
        severity = map_score_to_severity(score)
        plugin_id = random.randint(10000, 11000)
        plugin_name = random.choice(plugin_names)
        description = f"{plugin_name} detected on {host}."
        solution = f"Apply patch or update {plugin_name}."
        cve = random.choice(cves)

        writer.writerow({
            'Host': host,
            'IP': ip,
            'Port': port,
            'Protocol': protocol,
            'Severity': severity,
            'Score': score,
            'Plugin ID': plugin_id,
            'Plugin Name': plugin_name,
            'Description': description,
            'Solution': solution,
            'CVEs': cve
        })
