"""
Agent 3: Remediation Advisor
Input: Top priority CVE from Agent 2
Output: Step-by-step remediation guide
"""

import json
from typing import Dict, Optional, List
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


class RemediationAgent:
    """Agent 3: Remediation Advisor - Provides step-by-step fix instructions"""
    
    def __init__(self, llm_client=None):
        self.llm_client = llm_client
    
    def generate_remediation_steps(self, cve: Dict) -> List[str]:
        """Generate remediation steps for a CVE using LLM"""
        cve_id = cve.get('cve_id', '')
        description = cve.get('description', '')
        severity = cve.get('severity', '')
        technologies = ', '.join(cve.get('technologies', []))
        solution = cve.get('solution', '')
        cvss_score = cve.get('cvss_v3_score')
        
        # Prepare context for LLM
        context = f"""
CVE ID: {cve_id}
Severity: {severity}
CVSS Score: {cvss_score}
Technologies Affected: {technologies}
Description: {description}
Existing Solution: {solution if solution else 'No solution provided in CVE data'}
"""
        
        if self.llm_client:
            try:
                prompt = f"""You are a security remediation advisor. Based on the following CVE information, provide clear, actionable step-by-step remediation instructions.

{context}

Provide 5-7 specific remediation steps. Include:
1. Immediate actions (if any)
2. Update/upgrade instructions
3. Configuration changes
4. Verification steps
5. Best practices

Format each step clearly with numbers. Be specific about commands, versions, and actions."""

                response = self.llm_client.chat.completions.create(
                    model=LLM_MODEL,
                    messages=[
                        {"role": "system", "content": "You are a cybersecurity expert providing remediation guidance. Be clear, specific, and actionable."},
                        {"role": "user", "content": prompt}
                    ],
                    max_tokens=800,
                    temperature=0.3
                )
                
                steps_text = response.choices[0].message.content.strip()
                # Parse steps (split by numbers or newlines)
                steps = self._parse_steps(steps_text)
                return steps
                
            except Exception as e:
                print(f"[WARNING] LLM generation failed: {e}. Using template-based steps.")
                return self._generate_template_steps(cve)
        else:
            # Fallback to template-based steps
            return self._generate_template_steps(cve)
    
    def _parse_steps(self, text: str) -> List[str]:
        """Parse steps from LLM response"""
        lines = text.split('\n')
        steps = []
        
        for line in lines:
            line = line.strip()
            if line and (line[0].isdigit() or line.startswith('-') or line.startswith('*')):
                # Remove numbering
                step = line.split('.', 1)[-1].strip()
                if step:
                    steps.append(step)
        
        return steps if steps else [text]  # Return original if parsing fails
    
    def _generate_template_steps(self, cve: Dict) -> List[str]:
        """Generate template-based remediation steps"""
        technologies = cve.get('technologies', [])
        severity = cve.get('severity', '')
        
        steps = [
            f"1. IMMEDIATE ACTION: Review the {cve.get('cve_id')} vulnerability affecting {', '.join(technologies[:2])}",
            f"2. ASSESS IMPACT: This is a {severity} severity vulnerability. Evaluate your system's exposure",
            f"3. CHECK VERSIONS: Verify the affected software versions in your environment match the vulnerable versions",
        ]
        
        if cve.get('solution'):
            steps.append(f"4. APPLY FIX: {cve.get('solution')}")
        else:
            steps.append("4. UPDATE SOFTWARE: Upgrade to the latest patched version of the affected software")
        
        steps.extend([
            f"5. VERIFY PATCH: Test the update in a staging environment before production deployment",
            f"6. MONITOR: Set up monitoring for any exploitation attempts related to {cve.get('cve_id')}",
            f"7. DOCUMENT: Record the remediation actions taken and update your security documentation"
        ])
        
        return steps
    
    def format_remediation_guide(self, cve: Dict, steps: List[str]) -> str:
        """Format the complete remediation guide"""
        output = f"\n{'='*60}\n"
        output += f"REMEDIATION GUIDE: {cve.get('cve_id')}\n"
        output += f"{'='*60}\n\n"
        
        output += f"CVE ID: {cve.get('cve_id')}\n"
        output += f"Severity: {cve.get('severity')}\n"
        output += f"CVSS Score: {cve.get('cvss_v3_score')}\n"
        output += f"Priority: {cve.get('priority', 'HIGH')}\n"
        output += f"Affected Technologies: {', '.join(cve.get('technologies', []))}\n\n"
        
        output += f"Description:\n{cve.get('description', 'N/A')}\n\n"
        
        output += f"{'='*60}\n"
        output += "REMEDIATION STEPS:\n"
        output += f"{'='*60}\n\n"
        
        for step in steps:
            output += f"{step}\n\n"
        
        return output
    
    def process(self, cve: Dict) -> Dict:
        """Main processing function for Agent 3"""
        print(f"\n=== Agent 3: Remediation Advisor ===")
        print(f"Generating remediation guide for {cve.get('cve_id')}...\n")
        
        if not cve:
            return {
                'error': 'No CVE provided',
                'remediation_steps': [],
                'formatted_output': 'Error: No CVE data provided'
            }
        
        # Generate remediation steps
        steps = self.generate_remediation_steps(cve)
        
        print(f"[OK] Generated {len(steps)} remediation steps\n")
        
        # Format complete guide
        formatted_output = self.format_remediation_guide(cve, steps)
        
        return {
            'cve_id': cve.get('cve_id'),
            'remediation_steps': steps,
            'formatted_output': formatted_output,
            'step_count': len(steps)
        }


if __name__ == "__main__":
    # Example usage (for testing - normally receives input from Agent 2)
    print("Agent 3: Remediation Advisor")
    print("Note: This agent requires input from Agent 2")
    print("Run the main orchestrator to test the full chain\n")

