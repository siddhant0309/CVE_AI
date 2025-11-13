"""
Generate sample CVE data for POC with complete fields
Based on realistic CVE structure for 2025
"""

import json
import random
from pathlib import Path

# Sample technologies for realistic CVEs
TECHNOLOGIES = [
    "Python", "PostgreSQL", "React", "Node.js", "Django", "Flask",
    "MySQL", "MongoDB", "Redis", "Docker", "Kubernetes", "Nginx",
    "Apache", "TensorFlow", "PyTorch", "Java", "Spring Boot",
    "PHP", "WordPress", "Ruby", "Rails", "Go", "Rust", "C++",
    "JavaScript", "TypeScript", "Angular", "Vue.js", "Express",
    "Elasticsearch", "Kafka", "Zookeeper", "Cassandra", "Grafana"
]

# Sample vulnerability types
VULN_TYPES = [
    "SQL injection", "Cross-site scripting (XSS)", "Remote code execution",
    "Path traversal", "Authentication bypass", "Privilege escalation",
    "Denial of service", "Information disclosure", "CSRF", "XXE injection",
    "Server-side request forgery (SSRF)", "Command injection"
]

# Sample solutions
SOLUTIONS = [
    "Update to version {version} or later which contains the security patch.",
    "Apply the provided security patch and restart the service.",
    "Disable the affected feature until a patch is available.",
    "Implement input validation and sanitization.",
    "Upgrade to the latest stable release which addresses this vulnerability.",
    "Review and apply security configuration changes as per the advisory."
]

def generate_cve_data(cve_number: int) -> dict:
    """Generate a single CVE with complete data"""
    cve_id = f"CVE-2025-{cve_number:04d}"
    
    # Randomly select technologies
    num_techs = random.randint(1, 3)
    selected_techs = random.sample(TECHNOLOGIES, num_techs)
    vuln_type = random.choice(VULN_TYPES)
    
    # Generate description
    description = f"A {vuln_type} vulnerability has been discovered in {selected_techs[0]}. "
    description += f"This vulnerability could allow an attacker to {random.choice(['gain unauthorized access', 'execute arbitrary code', 'access sensitive data', 'cause denial of service'])}. "
    description += f"Affected versions include {selected_techs[0]} versions {random.uniform(1.0, 3.0):.1f} through {random.uniform(3.0, 5.0):.1f}."
    
    # Generate CVSS scores
    cvss_v3_score = round(random.uniform(4.0, 9.9), 1)
    cvss_v2_score = round(random.uniform(3.0, 9.0), 1)
    
    # Determine severity based on CVSS v3
    if cvss_v3_score >= 9.0:
        severity = "CRITICAL"
    elif cvss_v3_score >= 7.0:
        severity = "HIGH"
    elif cvss_v3_score >= 4.0:
        severity = "MEDIUM"
    else:
        severity = "LOW"
    
    # EPSS score (exploitation probability)
    epss_score = round(random.uniform(0.0, 1.0), 3)
    
    # KEV flag (10% chance of being in KEV list)
    kev_flag = random.random() < 0.1
    
    # Generate solution
    solution = random.choice(SOLUTIONS).format(version=f"{random.uniform(3.0, 6.0):.1f}")
    
    # Generate affected products
    affected_products = []
    for tech in selected_techs:
        vendor = random.choice(["", "Apache", "Microsoft", "Oracle", "Google", "MongoDB Inc"])
        if vendor:
            affected_products.append(f"{vendor}/{tech}")
        else:
            affected_products.append(tech)
    
    # Generate references
    references = [
        {"url": f"https://github.com/advisories/{cve_id}", "name": "GitHub Advisory"},
        {"url": f"https://nvd.nist.gov/vuln/detail/{cve_id}", "name": "NVD Entry"}
    ]
    
    return {
        'cve_id': cve_id,
        'description': description,
        'cvss_v3_score': cvss_v3_score,
        'cvss_v2_score': cvss_v2_score,
        'severity': severity,
        'affected_products': affected_products,
        'technologies': selected_techs,
        'solution': solution,
        'references': references,
        'kev_flag': kev_flag,
        'epss_score': epss_score,
        'vulnerability_type': vuln_type
    }

def generate_sample_cves(count: int = 50) -> list:
    """Generate multiple sample CVEs"""
    print(f"Generating {count} sample CVEs...\n")
    
    cves = []
    start_number = random.randint(1, 100)
    
    for i in range(count):
        cve_number = start_number + i
        cve = generate_cve_data(cve_number)
        cves.append(cve)
        print(f"[{i+1}/{count}] Generated {cve['cve_id']} - {cve['severity']} - {', '.join(cve['technologies'])}")
    
    return cves

def save_cves(cves: list, filename: str = "data/cves_2025.json"):
    """Save CVEs to JSON file"""
    Path("data").mkdir(exist_ok=True)
    
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(cves, f, indent=2, ensure_ascii=False)
    
    print(f"\n[OK] Saved {len(cves)} CVEs to {filename}\n")

if __name__ == "__main__":
    print("=== Generating Sample CVE Data for POC ===\n")
    
    # Generate 50 sample CVEs
    cves = generate_sample_cves(count=50)
    
    # Save to file
    save_cves(cves)
    
    # Print summary
    print("=== Summary ===")
    print(f"Total CVEs: {len(cves)}")
    print(f"CVEs with CRITICAL severity: {sum(1 for cve in cves if cve['severity'] == 'CRITICAL')}")
    print(f"CVEs with HIGH severity: {sum(1 for cve in cves if cve['severity'] == 'HIGH')}")
    print(f"CVEs in KEV: {sum(1 for cve in cves if cve['kev_flag'])}")
    print(f"Unique technologies: {len(set(tech for cve in cves for tech in cve['technologies']))}")
    print("\nSample technologies:")
    all_techs = set(tech for cve in cves for tech in cve['technologies'])
    print(f"  {', '.join(list(all_techs)[:15])}")
    print("\n[OK] Sample CVE data generation complete!")

