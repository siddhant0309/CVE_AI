"""
Script to fetch 50 CVE files from 2025 from CVEProject/cvelistV5 repository
Filters for CVEs with complete data (CVSS, KEV, solution, etc.)
"""

import os
import json
import random
import requests
from pathlib import Path
from typing import List, Dict, Optional

# GitHub repository details
REPO_OWNER = "CVEProject"
REPO_NAME = "cvelistV5"
BRANCH = "main"
CVE_PATH = "cves/2025"

# GitHub API base URL
GITHUB_API_BASE = "https://api.github.com/repos"

def get_file_list_from_directory(year: str = "2025") -> List[str]:
    """Get list of all CVE JSON files from 2025 directory"""
    print(f"Fetching list of CVE files from {year}...")
    
    # CVE structure: cves/2025/CVE-2025-XXXXXX/CVE-2025-XXXXXX.json
    # Or: cves/2025/XXXX/CVE-2025-XXXXXX.json
    
    url = f"{GITHUB_API_BASE}/{REPO_OWNER}/{REPO_NAME}/contents/cves/{year}"
    
    all_json_files = []
    
    try:
        response = requests.get(url)
        response.raise_for_status()
        items = response.json()
        
        # First check if there are subdirectories (year/month structure)
        for item in items:
            if item['type'] == 'dir':
                # It's a subdirectory, explore it
                subdir_name = item['name']
                subdir_url = f"{GITHUB_API_BASE}/{REPO_OWNER}/{REPO_NAME}/contents/cves/{year}/{subdir_name}"
                try:
                    subdir_response = requests.get(subdir_url)
                    subdir_response.raise_for_status()
                    subdir_items = subdir_response.json()
                    
                    for subitem in subdir_items:
                        if subitem['type'] == 'file' and subitem['name'].endswith('.json'):
                            file_path = f"cves/{year}/{subdir_name}/{subitem['name']}"
                            all_json_files.append(file_path)
                        elif subitem['type'] == 'dir':
                            # Another level deep (like CVE-2025-XXXXXX/)
                            deep_dir_name = subitem['name']
                            deep_dir_url = f"{GITHUB_API_BASE}/{REPO_OWNER}/{REPO_NAME}/contents/cves/{year}/{subdir_name}/{deep_dir_name}"
                            try:
                                deep_response = requests.get(deep_dir_url)
                                deep_response.raise_for_status()
                                deep_items = deep_response.json()
                                
                                for deep_item in deep_items:
                                    if deep_item['type'] == 'file' and deep_item['name'].endswith('.json'):
                                        file_path = f"cves/{year}/{subdir_name}/{deep_dir_name}/{deep_item['name']}"
                                        all_json_files.append(file_path)
                            except:
                                pass
                except Exception as e:
                    print(f"  Error exploring subdirectory {subdir_name}: {e}")
                    continue
            elif item['type'] == 'file' and item['name'].endswith('.json'):
                # Direct file in year directory
                file_path = f"cves/{year}/{item['name']}"
                all_json_files.append(file_path)
        
        print(f"Found {len(all_json_files)} CVE files in {year} (explored subdirectories)")
        return all_json_files[:200]  # Limit to first 200 for performance
        
    except Exception as e:
        print(f"Error fetching file list: {e}")
        return []

def download_cve_file(file_path: str) -> Optional[Dict]:
    """Download a single CVE JSON file from GitHub"""
    url = f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/{BRANCH}/{file_path}"
    
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"Error downloading {file_path}: {e}")
        return None

def has_required_fields(cve_data: Dict) -> bool:
    """Check if CVE has all required fields"""
    required_checks = {
        'cve_id': False,
        'description': False,
        'cvss': False,
        'affected_products': False
    }
    
    # Check for CVE ID
    if 'cveMetadata' in cve_data and 'cveId' in cve_data['cveMetadata']:
        required_checks['cve_id'] = True
    
    # Check for description
    if 'containers' in cve_data:
        cna = cve_data['containers'].get('cna', {})
        descriptions = cna.get('descriptions', [])
        if descriptions:
            required_checks['description'] = True
    
    # Check for CVSS scores
    if 'containers' in cve_data:
        cna = cve_data['containers'].get('cna', {})
        metrics = cna.get('metrics', [])
        if metrics:
            required_checks['cvss'] = True
    
    # Check for affected products/software
    if 'containers' in cve_data:
        cna = cve_data['containers'].get('cna', {})
        affected = cna.get('affected', [])
        if affected:
            required_checks['affected_products'] = True
    
    return all(required_checks.values())

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
        
        # Extract solution/remediation (often in solutions or references)
        solutions = cna.get('solutions', [])
        solution_text = ''
        if solutions:
            solution_text = solutions[0].get('text', '')
        
        # Extract references (might contain solution info)
        references = cna.get('references', [])
        
        # For KEV flag - we'll need to check against CISA KEV list separately
        # or it might be in the CVE data structure
        kev_flag = False  # Default, will be enriched later if available
        
        # Extract EPSS data (might not be in CVE JSON, will need separate source)
        epss_score = None
        
        structured_data = {
            'cve_id': cve_id,
            'description': description,
            'cvss_v3_score': cvss_v3_score,
            'cvss_v2_score': cvss_v2_score,
            'severity': severity,
            'affected_products': affected_products,
            'technologies': list(set(technologies)),  # Remove duplicates
            'solution': solution_text,
            'references': references,
            'kev_flag': kev_flag,
            'epss_score': epss_score,
            'raw_data': cve_data  # Keep raw data for reference
        }
        
        return structured_data
        
    except Exception as e:
        print(f"Error extracting CVE data: {e}")
        return None

def fetch_cves(target_count: int = 50) -> List[Dict]:
    """Fetch and filter CVEs from 2025"""
    print(f"\n=== Fetching {target_count} CVEs from 2025 ===\n")
    
    # Get list of files
    json_files = get_file_list_from_directory("2025")
    
    if not json_files:
        print("No CVE files found!")
        return []
    
    # Shuffle for randomness
    random.shuffle(json_files)
    
    valid_cves = []
    processed = 0
    
    print(f"Processing CVEs (looking for {target_count} with complete data)...\n")
    
    for file_path in json_files:
        if len(valid_cves) >= target_count:
            break
            
        processed += 1
        filename = file_path.split('/')[-1]
        
        print(f"[{processed}/{len(json_files)}] Processing {filename}...", end=' ')
        
        # Download CVE file (file_path is already full path)
        cve_data = download_cve_file(file_path)
        
        if not cve_data:
            print("Failed to download")
            continue
        
        # Check if has required fields
        if not has_required_fields(cve_data):
            print("Missing required fields")
            continue
        
        # Extract structured data
        structured = extract_cve_data(cve_data)
        
        if structured:
            valid_cves.append(structured)
            print(f"[OK] Added (Total: {len(valid_cves)})")
        else:
            print("Failed to extract")
    
    print(f"\n=== Successfully fetched {len(valid_cves)} CVEs ===\n")
    return valid_cves

def save_cves_to_file(cves: List[Dict], output_file: str = "cves_2025.json"):
    """Save CVEs to JSON file"""
    output_path = Path(output_file)
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(cves, f, indent=2, ensure_ascii=False)
    print(f"Saved {len(cves)} CVEs to {output_file}")

if __name__ == "__main__":
    # Create output directory
    os.makedirs("data", exist_ok=True)
    
    # Fetch CVEs
    cves = fetch_cves(target_count=50)
    
    if cves:
        # Save to file
        save_cves_to_file(cves, "data/cves_2025.json")
        
        # Print summary
        print("\n=== Summary ===")
        print(f"Total CVEs fetched: {len(cves)}")
        print(f"CVEs with CVSS v3: {sum(1 for cve in cves if cve.get('cvss_v3_score'))}")
        print(f"CVEs with affected products: {sum(1 for cve in cves if cve.get('affected_products'))}")
        print(f"Unique technologies: {len(set(tech for cve in cves for tech in cve.get('technologies', [])))}")
    else:
        print("No valid CVEs found!")

