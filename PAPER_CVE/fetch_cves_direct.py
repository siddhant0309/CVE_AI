"""
Direct CVE fetcher - downloads CVEs directly from raw GitHub URLs
Avoids API rate limits by using direct file access
"""

import json
import random
import requests
import time
from pathlib import Path
from typing import List, Dict, Optional

REPO_OWNER = "CVEProject"
REPO_NAME = "cvelistV5"
BRANCH = "main"
BASE_URL = f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/{BRANCH}/cves/2025"

def download_cve_direct(cve_id: str) -> Optional[Dict]:
    """Download CVE directly from raw GitHub URL"""
    # CVE structure: cves/2025/XXXX/CVE-2025-XXXXXX/CVE-2025-XXXXXX.json
    # Extract number part from CVE ID
    if not cve_id.startswith("CVE-2025-"):
        return None
    
    number_part = cve_id.replace("CVE-2025-", "")
    
    # Determine subdirectory (first few digits)
    if len(number_part) >= 4:
        subdir = number_part[:4] + "xxx"
    elif len(number_part) >= 3:
        subdir = number_part[:3] + "xxx"
    elif len(number_part) >= 2:
        subdir = number_part[:2] + "xxx"
    else:
        subdir = number_part[0] + "xxx"
    
    # Try direct path: cves/2025/XXXX/CVE-2025-XXXXXX/CVE-2025-XXXXXX.json
    url = f"{BASE_URL}/{subdir}/{cve_id}/{cve_id}.json"
    
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            return response.json()
    except:
        pass
    
    return None

def extract_cve_data(cve_data: Dict) -> Optional[Dict]:
    """Extract and structure CVE data"""
    try:
        cve_metadata = cve_data.get('cveMetadata', {})
        cve_id = cve_metadata.get('cveId', '')
        
        containers = cve_data.get('containers', {})
        cna = containers.get('cna', {})
        
        # Extract description
        descriptions = cna.get('descriptions', [])
        description = ''
        if descriptions:
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break
            if not description and descriptions:
                description = descriptions[0].get('value', '')
        
        # Extract CVSS scores
        metrics = cna.get('metrics', [])
        cvss_v3_score = None
        cvss_v2_score = None
        severity = None
        
        for metric in metrics:
            if 'cvssV3_1' in metric or 'cvssV3_0' in metric:
                cvss_data = metric.get('cvssV3_1') or metric.get('cvssV3_0', {})
                cvss_v3_score = cvss_data.get('baseScore')
                severity = cvss_data.get('baseSeverity')
            elif 'cvssV2' in metric:
                cvss_v2_score = metric.get('cvssV2', {}).get('baseScore')
        
        # Extract affected products
        affected = cna.get('affected', [])
        affected_products = []
        technologies = []
        
        for item in affected:
            vendor = item.get('vendor', '')
            product = item.get('product', '')
            if product:
                full_name = f"{vendor}/{product}".strip('/')
                affected_products.append(full_name)
                technologies.append(product)
        
        # Extract solution/remediation
        solutions = cna.get('solutions', [])
        solution_text = ''
        if solutions:
            solution_text = solutions[0].get('text', '')
        
        # Extract references
        references = cna.get('references', [])
        
        # Default values
        kev_flag = False
        epss_score = None
        
        # Check if required fields exist
        if not cve_id or not description:
            return None
        
        structured_data = {
            'cve_id': cve_id,
            'description': description,
            'cvss_v3_score': cvss_v3_score,
            'cvss_v2_score': cvss_v2_score,
            'severity': severity,
            'affected_products': affected_products,
            'technologies': list(set(technologies)),
            'solution': solution_text,
            'references': references,
            'kev_flag': kev_flag,
            'epss_score': epss_score,
            'raw_data': cve_data
        }
        
        return structured_data
        
    except Exception as e:
        print(f"Error extracting CVE data: {e}")
        return None

def generate_cve_ids(start_range: int = 1, end_range: int = 10000, count: int = 300) -> List[str]:
    """Generate random CVE IDs in range - trying multiple formats"""
    ids = []
    
    # Try different number formats
    # Format 1: 4-digit (CVE-2025-0001)
    if end_range <= 9999:
        numbers_4dig = random.sample(range(start_range, min(1000, end_range)), min(50, 1000 - start_range))
        ids.extend([f"CVE-2025-{num:04d}" for num in numbers_4dig])
    
    # Format 2: 5-digit (CVE-2025-00001)
    if end_range > 1000:
        numbers_5dig = random.sample(range(1000, min(10000, end_range)), min(100, min(10000, end_range) - 1000))
        ids.extend([f"CVE-2025-{num:05d}" for num in numbers_5dig])
    
    # Format 3: 6-digit (CVE-2025-000001) 
    if end_range > 10000:
        numbers_6dig = random.sample(range(10000, end_range), min(150, end_range - 10000))
        ids.extend([f"CVE-2025-{num:06d}" for num in numbers_6dig])
    
    random.shuffle(ids)
    return ids[:count]

def fetch_cves_direct(target_count: int = 50) -> List[Dict]:
    """Fetch CVEs directly from raw GitHub URLs"""
    print(f"\n=== Fetching {target_count} CVEs from 2025 (direct download) ===\n")
    
    # Generate CVE IDs to try
    print("Generating CVE IDs to fetch...")
    cve_ids = generate_cve_ids(start_range=1, end_range=10000, count=200)
    print(f"Will try {len(cve_ids)} CVE IDs\n")
    
    valid_cves = []
    processed = 0
    
    print(f"Processing CVEs (looking for {target_count} with complete data)...\n")
    
    for cve_id in cve_ids:
        if len(valid_cves) >= target_count:
            break
        
        processed += 1
        print(f"[{processed}/{len(cve_ids)}] Trying {cve_id}...", end=' ')
        
        # Download CVE file
        cve_data = download_cve_direct(cve_id)
        
        if not cve_data:
            print("Not found")
            time.sleep(0.1)  # Small delay to avoid rate limiting
            continue
        
        # Extract structured data
        structured = extract_cve_data(cve_data)
        
        if structured:
            valid_cves.append(structured)
            print(f"[OK] Added (Total: {len(valid_cves)})")
        else:
            print("Missing required fields")
        
        time.sleep(0.1)  # Small delay between requests
    
    print(f"\n=== Successfully fetched {len(valid_cves)} CVEs ===\n")
    return valid_cves

def save_cves_to_file(cves: List[Dict], output_file: str = "data/cves_2025.json"):
    """Save CVEs to JSON file"""
    os.makedirs("data", exist_ok=True)
    output_path = Path(output_file)
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(cves, f, indent=2, ensure_ascii=False)
    print(f"[OK] Saved {len(cves)} CVEs to {output_file}")

if __name__ == "__main__":
    import os
    
    # Fetch CVEs
    cves = fetch_cves_direct(target_count=50)
    
    if cves:
        # Save to file
        save_cves_to_file(cves, "data/cves_2025.json")
        
        # Print summary
        print("\n=== Summary ===")
        print(f"Total CVEs fetched: {len(cves)}")
        print(f"CVEs with CVSS v3: {sum(1 for cve in cves if cve.get('cvss_v3_score'))}")
        print(f"CVEs with affected products: {sum(1 for cve in cves if cve.get('affected_products'))}")
        all_techs = set(tech for cve in cves for tech in cve.get('technologies', []))
        print(f"Unique technologies: {len(all_techs)}")
        print(f"Sample technologies: {list(all_techs)[:10]}")
    else:
        print("No valid CVEs found!")

