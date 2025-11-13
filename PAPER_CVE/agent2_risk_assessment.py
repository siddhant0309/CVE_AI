"""
Agent 2: Risk Assessment Analyst
Input: CVE List from Agent 1
Output: Prioritized/Ranked CVE list based on risk scoring
"""

import json
from typing import List, Dict
from openai import OpenAI
import os
from dotenv import load_dotenv

load_dotenv()

# Initialize LLM client
try:
    api_key = os.getenv("OPENAI_API_KEY")
    if api_key and api_key.strip():
        llm_client = OpenAI(api_key=api_key)
        LLM_MODEL = "gpt-3.5-turbo"
    else:
        llm_client = None
except:
    llm_client = None

# Load CVE data
CVE_DATA_FILE = "data/cves_2025.json"


class RiskAssessmentAgent:
    """Agent 2: Risk Assessment Analyst - Prioritizes CVEs by risk"""
    
    def __init__(self, llm_client=None):
        self.llm_client = llm_client
        self.cve_data = self._load_cve_data()
    
    def _load_cve_data(self) -> Dict:
        """Load full CVE data from JSON file"""
        try:
            with open(CVE_DATA_FILE, 'r', encoding='utf-8') as f:
                cves = json.load(f)
            # Create dictionary with CVE ID as key
            return {cve['cve_id']: cve for cve in cves}
        except Exception as e:
            print(f"[WARNING] Could not load CVE data: {e}")
            return {}
    
    def calculate_risk_score(self, cve: Dict) -> float:
        """Calculate composite risk score for a CVE"""
        score = 0.0
        
        # CVSS v3 Score (0-10) - 40% weight
        cvss_v3 = cve.get('cvss_v3_score')
        if cvss_v3:
            score += (cvss_v3 / 10.0) * 0.4
        
        # EPSS Score (0-1) - 30% weight
        epss = cve.get('epss_score')
        if epss is None:
            # If EPSS not available, estimate based on CVSS
            epss = (cvss_v3 / 10.0) * 0.7 if cvss_v3 else 0.3
        score += epss * 0.3
        
        # KEV Flag (boolean) - 20% weight
        if cve.get('kev_flag'):
            score += 0.2
        
        # Severity multiplier - 10% weight
        severity = cve.get('severity', '').upper()
        if severity == 'CRITICAL':
            score += 0.1
        elif severity == 'HIGH':
            score += 0.075
        elif severity == 'MEDIUM':
            score += 0.05
        else:
            score += 0.025
        
        # Cap at 1.0
        return min(score, 1.0)
    
    def prioritize_cves(self, cve_list: List[Dict]) -> List[Dict]:
        """Prioritize CVEs based on risk scores"""
        print(f"\n=== Agent 2: Risk Assessment Analyst ===")
        print(f"Analyzing {len(cve_list)} CVEs...\n")
        
        enriched_cves = []
        
        for cve_data in cve_list:
            cve_id = cve_data.get('cve_id')
            
            # Get full CVE data from our dataset
            full_cve = self.cve_data.get(cve_id, {})
            
            # Merge data
            enriched_cve = {
                'cve_id': cve_id,
                'description': cve_data.get('description') or full_cve.get('description', ''),
                'cvss_v3_score': cve_data.get('cvss_v3_score') or full_cve.get('cvss_v3_score'),
                'cvss_v2_score': full_cve.get('cvss_v2_score'),
                'severity': cve_data.get('severity') or full_cve.get('severity', ''),
                'technologies': cve_data.get('technologies', []),
                'affected_products': cve_data.get('affected_products', []),
                'epss_score': full_cve.get('epss_score'),
                'kev_flag': full_cve.get('kev_flag', False),
                'solution': full_cve.get('solution', ''),
                'similarity_score': cve_data.get('similarity_score', 0)
            }
            
            # Calculate risk score
            risk_score = self.calculate_risk_score(enriched_cve)
            enriched_cve['risk_score'] = risk_score
            
            # Determine priority level
            if risk_score >= 0.75:
                priority = 'CRITICAL'
            elif risk_score >= 0.55:
                priority = 'HIGH'
            elif risk_score >= 0.35:
                priority = 'MEDIUM'
            else:
                priority = 'LOW'
            
            enriched_cve['priority'] = priority
            enriched_cves.append(enriched_cve)
        
        # Sort by risk score (descending)
        prioritized_cves = sorted(enriched_cves, key=lambda x: x['risk_score'], reverse=True)
        
        # Add rank
        for i, cve in enumerate(prioritized_cves, 1):
            cve['rank'] = i
        
        print(f"[OK] Prioritized {len(prioritized_cves)} CVEs\n")
        return prioritized_cves
    
    def format_output(self, prioritized_cves: List[Dict]) -> str:
        """Format prioritized CVE results"""
        output = f"\n=== Prioritized CVE List ({len(prioritized_cves)} CVEs) ===\n\n"
        
        for cve in prioritized_cves[:10]:  # Show top 10
            output += f"Rank {cve['rank']}: {cve['cve_id']} - {cve['priority']} Priority\n"
            output += f"  Risk Score: {cve['risk_score']:.4f}\n"
            output += f"  CVSS v3: {cve['cvss_v3_score']}\n"
            output += f"  EPSS: {cve.get('epss_score', 'N/A')}\n"
            output += f"  KEV Flag: {'YES' if cve['kev_flag'] else 'NO'}\n"
            output += f"  Severity: {cve['severity']}\n"
            output += f"  Technologies: {', '.join(cve.get('technologies', []))}\n"
            output += "\n"
        
        return output
    
    def process(self, cve_list: List[Dict]) -> Dict:
        """Main processing function for Agent 2"""
        # Prioritize CVEs
        prioritized_cves = self.prioritize_cves(cve_list)
        
        # Format output
        formatted_output = self.format_output(prioritized_cves)
        
        return {
            'prioritized_cves': prioritized_cves,
            'top_priority_cve': prioritized_cves[0] if prioritized_cves else None,
            'count': len(prioritized_cves),
            'formatted_output': formatted_output
        }


if __name__ == "__main__":
    # Example usage (for testing - normally receives input from Agent 1)
    print("Agent 2: Risk Assessment Analyst")
    print("Note: This agent requires input from Agent 1")
    print("Run the main orchestrator to test the full chain\n")

