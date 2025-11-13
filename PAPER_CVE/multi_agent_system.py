"""
Multi-Agent System Orchestrator
Chains all three agents together with user input
"""

from agent1_cve_retrieval import CVERetrievalAgent, collection, embedding_model, llm_client as llm_client_1
from agent2_risk_assessment import RiskAssessmentAgent
from agent3_remediation import RemediationAgent
import json


class MultiAgentSystem:
    """Orchestrates all three agents"""
    
    def __init__(self):
        print("=" * 60)
        print("Initializing Multi-Agent CVE Analysis System")
        print("=" * 60)
        print()
        
        # Initialize all agents
        self.agent1 = CVERetrievalAgent(collection, embedding_model, llm_client_1)
        self.agent2 = RiskAssessmentAgent(llm_client_1)
        self.agent3 = RemediationAgent(llm_client_1)
        
        print("[OK] All agents initialized\n")
    
    def process(self, user_input: str, top_k: int = 10) -> Dict:
        """Process user input through all three agents"""
        
        print("\n" + "=" * 60)
        print("MULTI-AGENT CVE ANALYSIS PIPELINE")
        print("=" * 60)
        print(f"User Input: {user_input}\n")
        
        # ========================================
        # AGENT 1: CVE Retrieval Specialist
        # ========================================
        print("\n" + "-" * 60)
        print("STEP 1: Agent 1 - CVE Retrieval Specialist")
        print("-" * 60)
        
        agent1_result = self.agent1.process(user_input, top_k=top_k)
        
        if not agent1_result['cves']:
            return {
                'error': 'No CVEs found',
                'agent1_result': agent1_result,
                'agent2_result': None,
                'agent3_result': None
            }
        
        print(f"\n[OK] Agent 1 found {agent1_result['count']} relevant CVEs")
        print(f"Passing to Agent 2: {[cve['cve_id'] for cve in agent1_result['cves']]}")
        
        # ========================================
        # AGENT 2: Risk Assessment Analyst
        # ========================================
        print("\n" + "-" * 60)
        print("STEP 2: Agent 2 - Risk Assessment Analyst")
        print("-" * 60)
        
        agent2_result = self.agent2.process(agent1_result['cves'])
        
        print(f"\n[OK] Agent 2 prioritized {agent2_result['count']} CVEs")
        
        top_cve = agent2_result['top_priority_cve']
        if top_cve:
            print(f"Top Priority CVE: {top_cve['cve_id']} (Risk Score: {top_cve['risk_score']:.4f})")
            print(f"Passing to Agent 3: {top_cve['cve_id']}")
        
        # ========================================
        # AGENT 3: Remediation Advisor
        # ========================================
        print("\n" + "-" * 60)
        print("STEP 3: Agent 3 - Remediation Advisor")
        print("-" * 60)
        
        agent3_result = None
        if top_cve:
            agent3_result = self.agent3.process(top_cve)
            print(f"\n[OK] Agent 3 generated {agent3_result['step_count']} remediation steps")
        
        # ========================================
        # FINAL RESULTS
        # ========================================
        print("\n" + "=" * 60)
        print("FINAL RESULTS")
        print("=" * 60)
        
        return {
            'agent1_result': agent1_result,
            'agent2_result': agent2_result,
            'agent3_result': agent3_result,
            'summary': {
                'cves_found': agent1_result['count'],
                'cves_prioritized': agent2_result['count'],
                'top_cve': top_cve['cve_id'] if top_cve else None,
                'remediation_steps': agent3_result['step_count'] if agent3_result else 0
            }
        }
    
    def display_results(self, results: Dict):
        """Display formatted results"""
        print("\n" + "=" * 60)
        print("COMPLETE ANALYSIS RESULTS")
        print("=" * 60)
        
        # Agent 1 Results
        print("\n--- Agent 1: CVE Retrieval ---")
        print(results['agent1_result']['formatted_output'])
        
        # Agent 2 Results
        print("\n--- Agent 2: Risk Prioritization ---")
        print(results['agent2_result']['formatted_output'])
        
        # Agent 3 Results
        if results['agent3_result']:
            print("\n--- Agent 3: Remediation Guide ---")
            print(results['agent3_result']['formatted_output'])
        
        # Summary
        print("\n" + "=" * 60)
        print("SUMMARY")
        print("=" * 60)
        summary = results['summary']
        print(f"CVEs Found: {summary['cves_found']}")
        print(f"CVEs Prioritized: {summary['cves_prioritized']}")
        print(f"Top Priority CVE: {summary['top_cve']}")
        print(f"Remediation Steps Generated: {summary['remediation_steps']}")
        print()


def main():
    """Main function - Get user input and process"""
    system = MultiAgentSystem()
    
    print("\n" + "=" * 60)
    print("CVE MULTI-AGENT ANALYSIS SYSTEM")
    print("=" * 60)
    print("\nEnter your tech stack to analyze vulnerabilities:")
    print("Example: 'I'm using Python 3.9 and PostgreSQL 14'")
    print()
    
    # Get user input
    user_input = input("Your tech stack: ").strip()
    
    if not user_input:
        print("No input provided. Using default example...")
        user_input = "I'm using Python 3.9 and PostgreSQL 14 in my application"
        print(f"Using: {user_input}\n")
    
    # Process through all agents
    results = system.process(user_input, top_k=10)
    
    # Display results
    system.display_results(results)
    
    return results


if __name__ == "__main__":
    main()

