"""
Streamlit Conversational Chat UI for Multi-Agent CVE Analysis System
Agents run on-demand based on user questions
"""

import streamlit as st
import json
import re
from typing import List, Dict, Optional
from agent1_cve_retrieval import CVERetrievalAgent, collection, embedding_model, llm_client as llm_client_1
from agent2_risk_assessment import RiskAssessmentAgent
from agent3_remediation import RemediationAgent
from openai import OpenAI
import os
from dotenv import load_dotenv

load_dotenv()

# Initialize LLM client for intent detection
try:
    api_key = os.getenv("OPENAI_API_KEY")
    if api_key and api_key.strip():
        llm_client_intent = OpenAI(api_key=api_key)
        LLM_MODEL = "gpt-3.5-turbo"
    else:
        llm_client_intent = None
except:
    llm_client_intent = None

# Page config
st.set_page_config(
    page_title="CVE Multi-Agent Analysis System",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize session state
if 'messages' not in st.session_state:
    st.session_state.messages = []
if 'agents_initialized' not in st.session_state:
    st.session_state.agents_initialized = False
if 'agent1' not in st.session_state:
    st.session_state.agent1 = None
if 'agent2' not in st.session_state:
    st.session_state.agent2 = None
if 'agent3' not in st.session_state:
    st.session_state.agent3 = None
if 'last_cves' not in st.session_state:
    st.session_state.last_cves = None  # Store CVEs from Agent 1
if 'last_prioritized' not in st.session_state:
    st.session_state.last_prioritized = None  # Store prioritized CVEs from Agent 2

# Initialize agents (only once)
@st.cache_resource
def initialize_agents():
    """Initialize all agents"""
    try:
        agent1 = CVERetrievalAgent(collection, embedding_model, llm_client_1)
        agent2 = RiskAssessmentAgent(llm_client_1)
        agent3 = RemediationAgent(llm_client_1)
        return agent1, agent2, agent3
    except Exception as e:
        st.error(f"Error initializing agents: {e}")
        return None, None, None

# Initialize agents
if not st.session_state.agents_initialized:
    with st.spinner("Initializing agents..."):
        agent1, agent2, agent3 = initialize_agents()
        if agent1 and agent2 and agent3:
            st.session_state.agent1 = agent1
            st.session_state.agent2 = agent2
            st.session_state.agent3 = agent3
            st.session_state.agents_initialized = True

# Sidebar
with st.sidebar:
    st.title("🔒 CVE Analysis System")
    st.markdown("---")
    st.markdown("### Multi-Agent Architecture")
    st.markdown("""
    **Agent 1:** CVE Retrieval Specialist
    - Finds CVEs matching your tech stack
    
    **Agent 2:** Risk Assessment Analyst
    - Prioritizes CVEs by risk score
    
    **Agent 3:** Remediation Advisor
    - Provides fix steps for top priority CVE
    """)
    st.markdown("---")
    
    if st.button("🗑️ Clear Chat History"):
        st.session_state.messages = []
        st.session_state.last_cves = None
        st.session_state.last_prioritized = None
        st.rerun()
    
    st.markdown("---")
    st.markdown("### About")
    st.markdown("Conversational chat - Ask about bugs, risks, and fixes step by step.")
    st.markdown("\n**Demo Flow:**")
    st.markdown("1. Ask about bugs in tech stack")
    st.markdown("2. Ask about risk levels")
    st.markdown("3. Ask for fixes")

# Main title
st.title("🔒 CVE Multi-Agent Analysis System")
st.markdown("💬 **Conversational Chat** - Ask about bugs, risks, and fixes step by step")

def extract_technology(user_message: str) -> List[str]:
    """Extract technology keywords from user message"""
    message_lower = user_message.lower()
    tech_keywords = []
    
    # Common technologies in our database
    all_techs = [
        'python', 'node.js', 'nodejs', 'react', 'postgresql', 'mongodb', 'redis',
        'docker', 'kubernetes', 'nginx', 'apache', 'tensorflow', 'pytorch', 'java',
        'spring boot', 'php', 'wordpress', 'ruby', 'rails', 'go', 'rust', 'c++',
        'javascript', 'typescript', 'angular', 'vue.js', 'express', 'django', 'flask',
        'elasticsearch', 'kafka', 'zookeeper', 'cassandra', 'grafana', 'mysql', 'airflow'
    ]
    
    for tech in all_techs:
        if tech.lower() in message_lower:
            if tech.lower() in ['node.js', 'nodejs']:
                tech_keywords.append('Node.js')
            else:
                tech_keywords.append(tech.title() if tech.islower() else tech)
    
    return tech_keywords

def cves_match_technology(cves: List[Dict], tech_keywords: List[str]) -> bool:
    """Check if CVEs match the technology keywords"""
    if not cves or not tech_keywords:
        return False
    
    tech_keywords_lower = [kw.lower() for kw in tech_keywords]
    
    for cve in cves:
        cve_techs = [t.lower() for t in cve.get('technologies', [])]
        if any(tech_kw in ' '.join(cve_techs) or any(tech_kw in ct for ct in cve_techs) for tech_kw in tech_keywords_lower):
            return True
    return False

def extract_cve_id(user_message: str) -> Optional[str]:
    """Extract CVE ID from user message if mentioned"""
    # Pattern to match CVE IDs: CVE-YYYY-NNNNN (where YYYY is year, NNNNN is any digits)
    cve_pattern = r'CVE-\d{4}-\d+'
    matches = re.findall(cve_pattern, user_message, re.IGNORECASE)
    if matches:
        return matches[0].upper()  # Return first match in uppercase
    return None

def is_vague_query(user_query: str, intent: str) -> Dict:
    """Check if query is too vague and needs clarification"""
    result = {
        'is_vague': False,
        'reason': '',
        'clarification_message': ''
    }
    
    # Only check for remediation intent (fixes/solutions)
    if intent != 'remediation':
        return result
    
    # Extract CVE ID from query
    cve_id = extract_cve_id(user_query)
    
    # Extract technology
    tech_keywords = extract_technology(user_query)
    
    # Check if query is vague
    vague_patterns = [
        r'fix.*for.*cve',
        r'solution.*for.*cve',
        r'remediation.*for.*cve',
        r'how.*to.*fix.*cve',
        r'provide.*fix.*for',
        r'give.*fix.*for',
        r'fix.*for.*\w+.*cve',
        r'solution.*for.*\w+.*cve'
    ]
    
    query_lower = user_query.lower()
    is_pattern_vague = any(re.search(pattern, query_lower) for pattern in vague_patterns)
    
    # If asking for fixes but:
    # 1. No specific CVE ID mentioned AND
    # 2. Matches vague pattern AND
    # 3. No prioritized CVEs stored OR stored CVEs don't match technology
    if is_pattern_vague and not cve_id:
        # Check if we have stored prioritized CVEs that match
        has_matching_cves = False
        if st.session_state.last_prioritized and tech_keywords:
            prioritized_match = cves_match_technology(st.session_state.last_prioritized, tech_keywords)
            if prioritized_match:
                has_matching_cves = True
        
        if not has_matching_cves:
            result['is_vague'] = True
            tech_display = ', '.join(tech_keywords) if tech_keywords else 'your technology'
            
            # Build clarification message
            if tech_keywords:
                result['clarification_message'] = f"""❓ **Which {tech_display} CVE specifically?**

I found multiple {tech_display} CVEs. Please specify which one you want fixes for:

**Option 1:** Provide the specific CVE ID (e.g., `CVE-2025-0001`)

**Option 2:** Ask me to:
1. First find {tech_display} CVEs
2. Then assess their risks
3. Then I'll provide fixes for the top priority one

**Example:** "find {tech_keywords[0]} CVEs" or "CVE-2025-0001 fixes"
"""
            else:
                result['clarification_message'] = f"""❓ **Which CVE specifically?**

I need more information. Please specify:

**Option 1:** Provide the specific CVE ID (e.g., `CVE-2025-0001`)

**Option 2:** Mention a technology first:
- "fix for Python CVE-2025-0001"
- "remediation for Node.js CVE-2025-0061"

**Option 3:** Ask me to find CVEs first:
- "find Python CVEs" → "assess risks" → "provide fixes"
"""
            result['reason'] = 'Query too vague - no specific CVE ID mentioned'
    
    return result

def search_cve_by_id(cve_id: str) -> Optional[Dict]:
    """Search for a specific CVE by ID in the vector database"""
    try:
        # Try to get CVE by ID from collection
        results = collection.get(ids=[cve_id])
        
        if results['ids'] and len(results['ids']) > 0:
            # Found CVE by ID
            metadata = results['metadatas'][0]
            document = results['documents'][0]
            
            # Reconstruct CVE dictionary from metadata
            cve = {
                'cve_id': metadata.get('cve_id', cve_id),
                'description': metadata.get('description', ''),
                'cvss_v3_score': metadata.get('cvss_v3_score'),
                'cvss_v2_score': metadata.get('cvss_v2_score'),
                'severity': metadata.get('severity', ''),
                'technologies': metadata.get('technologies', '').split(', ') if metadata.get('technologies') else [],
                'affected_products': metadata.get('affected_products', '').split(', ') if metadata.get('affected_products') else [],
                'has_solution': metadata.get('has_solution', False),
                'kev_flag': metadata.get('kev_flag', False),
                'epss_score': metadata.get('epss_score'),
                'similarity_score': 1.0,  # Perfect match
                'document': document
            }
            return cve
    except Exception as e:
        pass
    
    return None

def detect_intent(user_message: str) -> str:
    """Detect user intent to determine which agent to use"""
    message_lower = user_message.lower()
    
    # Check for risk assessment keywords FIRST (more specific)
    risk_keywords = ['risk', 'priority', 'prioritize', 'severity', 'dangerous', 'danger', 'risk level', 'risk levels', 'how dangerous', 'what risk']
    if any(word in message_lower for word in risk_keywords):
        return 'risk_assessment'
    
    # Check for remediation keywords SECOND (more specific)
    fix_keywords = ['fix', 'solution', 'remedy', 'patch', 'remediation', 'remediate', 'how to fix', 'provide fix', 'can you provide', 'fix for', 'steps', 'how to', 'remediation steps']
    if any(word in message_lower for word in fix_keywords):
        return 'remediation'
    
    # If LLM available, use it for better detection
    if not llm_client_intent:
        # Fallback - check for CVE retrieval keywords
        if any(word in message_lower for word in ['bug', 'vulnerability', 'cve', 'security issue', 'find', 'help', 'experiencing', 'what', 'cves in']):
            return 'cve_retrieval'
        return 'cve_retrieval'  # Default
    
    try:
        prompt = f"""Analyze the user's message and determine which agent should respond:
- "cve_retrieval": User is asking about finding bugs, vulnerabilities, CVEs, security issues, or tech stack problems
- "risk_assessment": User is asking about risk levels, priorities, severity, danger levels, or threat levels
- "remediation": User is asking for fixes, solutions, patches, remediation steps, or how to fix something

User message: "{user_message}"

Respond with ONLY one word: cve_retrieval, risk_assessment, or remediation"""

        response = llm_client_intent.chat.completions.create(
            model=LLM_MODEL,
            messages=[
                {"role": "system", "content": "You are an intent classifier. Respond with only the agent name."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=20,
            temperature=0.1
        )
        
        intent = response.choices[0].message.content.strip().lower()
        if 'risk' in intent:
            return 'risk_assessment'
        elif 'remediation' in intent or 'fix' in intent:
            return 'remediation'
        else:
            return 'cve_retrieval'
    except:
        # Fallback
        return 'cve_retrieval'

def planner_agent(user_query: str, intent: str) -> Dict:
    """Planner Agent: Plans which agents to run and in what order"""
    # Extract technology from query
    tech_keywords = extract_technology(user_query)
    
    # Extract CVE ID if mentioned
    cve_id = extract_cve_id(user_query)
    
    plan = {
        'need_agent1': False,
        'need_agent2': False,
        'need_agent3': False,
        'tech_keywords': tech_keywords,
        'cve_id': cve_id,
        'is_vague': False,
        'vague_info': None,
        'reason': ''
    }
    
    # Check for vague queries first
    vague_check = is_vague_query(user_query, intent)
    if vague_check['is_vague']:
        plan['is_vague'] = True
        plan['vague_info'] = vague_check
        return plan
    
    # Check if stored CVEs match the technology in query
    stored_cves_match = False
    if st.session_state.last_cves and tech_keywords:
        stored_cves_match = cves_match_technology(st.session_state.last_cves, tech_keywords)
    
    # Planning logic based on intent
    if intent == 'cve_retrieval':
        # Always need Agent 1 for new queries
        plan['need_agent1'] = True
        plan['reason'] = 'Finding CVEs for requested technology'
        
    elif intent == 'risk_assessment':
        if not st.session_state.last_cves:
            # No CVEs stored - need Agent 1 first
            plan['need_agent1'] = True
            plan['need_agent2'] = True
            plan['reason'] = 'No CVEs found. Finding CVEs first, then assessing risks.'
        elif tech_keywords and not stored_cves_match:
            # Stored CVEs don't match technology - need Agent 1 first
            plan['need_agent1'] = True
            plan['need_agent2'] = True
            plan['reason'] = f'Stored CVEs don\'t match "{tech_keywords[0] if tech_keywords else "requested technology"}". Finding new CVEs first.'
        else:
            # CVEs already match - just need Agent 2
            plan['need_agent2'] = True
            plan['reason'] = 'Using stored CVEs for risk assessment'
            
    elif intent == 'remediation':
        if not st.session_state.last_prioritized:
            # No prioritized CVEs - might need Agent 1 and Agent 2 first
            if not st.session_state.last_cves:
                # No CVEs at all - need full chain
                plan['need_agent1'] = True
                plan['need_agent2'] = True
                plan['need_agent3'] = True
                plan['reason'] = 'No CVEs found. Running full chain: Find CVEs → Prioritize → Generate fixes.'
            elif tech_keywords and not stored_cves_match:
                # Stored CVEs don't match - need Agent 1 and Agent 2
                plan['need_agent1'] = True
                plan['need_agent2'] = True
                plan['need_agent3'] = True
                plan['reason'] = f'Stored CVEs don\'t match "{tech_keywords[0] if tech_keywords else "requested technology"}". Finding new CVEs first.'
            else:
                # Have CVEs but need prioritization - Agent 2 and 3
                plan['need_agent2'] = True
                plan['need_agent3'] = True
                plan['reason'] = 'Prioritizing CVEs, then generating fixes'
        else:
            # Have prioritized CVEs - check if they match technology
            if tech_keywords:
                prioritized_techs = []
                if st.session_state.last_prioritized:
                    for cve in st.session_state.last_prioritized:
                        prioritized_techs.extend([t.lower() for t in cve.get('technologies', [])])
                
                prioritized_match = any(kw.lower() in ' '.join(prioritized_techs) for kw in tech_keywords)
                
                if not prioritized_match:
                    # Prioritized CVEs don't match - need full chain
                    plan['need_agent1'] = True
                    plan['need_agent2'] = True
                    plan['need_agent3'] = True
                    plan['reason'] = f'Prioritized CVEs don\'t match "{tech_keywords[0]}". Finding new CVEs first.'
                else:
                    # Prioritized CVEs match - just need Agent 3
                    plan['need_agent3'] = True
                    plan['reason'] = 'Using stored prioritized CVEs for remediation'
            else:
                # No technology mentioned - use stored prioritized CVEs
                plan['need_agent3'] = True
                plan['reason'] = 'Using stored prioritized CVEs for remediation'
    
    return plan

# Display chat history
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])
        
        # Display detailed agent results in chat
        if "agent_results" in message:
            results = message["agent_results"]
            
            # Agent 1 Results - Show in chat
            if "agent1_result" in results:
                agent1_result = results['agent1_result']
                st.markdown("---")
                st.markdown("### 🔍 Agent 1: CVE Retrieval Results")
                st.markdown(f"**Tech Stack Extracted:** {agent1_result.get('tech_stack', 'N/A')}")
                st.markdown(f"**Total CVEs Found:** {agent1_result.get('count', 0)}")
                
                if agent1_result.get('cves'):
                    st.markdown("\n**Relevant CVEs:**")
                    for i, cve in enumerate(agent1_result['cves'][:10], 1):
                        st.markdown(f"\n**{i}. {cve['cve_id']}** - {cve.get('severity', 'N/A')}")
                        st.markdown(f"   - CVSS v3: {cve.get('cvss_v3_score', 'N/A')}")
                        st.markdown(f"   - Technologies: {', '.join(cve.get('technologies', []))}")
                        st.markdown(f"   - Similarity Score: {cve.get('similarity_score', 0):.4f}")
                        st.markdown(f"   - Description: {cve.get('description', '')[:200]}...")
            
            # Agent 2 Results - Show in chat
            if "agent2_result" in results:
                agent2_result = results['agent2_result']
                prioritized = agent2_result.get('prioritized_cves', [])
                
                st.markdown("---")
                st.markdown("### 📊 Agent 2: Risk Prioritization Results")
                st.markdown(f"**CVEs Prioritized:** {len(prioritized)}")
                
                if prioritized:
                    st.markdown("\n**Prioritized CVE List:**")
                    for cve in prioritized[:10]:
                        st.markdown(f"\n**Rank {cve['rank']}: {cve['cve_id']}**")
                        st.markdown(f"   - Priority Level: **{cve.get('priority', 'N/A')}**")
                        st.markdown(f"   - Risk Score: {cve.get('risk_score', 0):.4f}")
                        st.markdown(f"   - CVSS v3: {cve.get('cvss_v3_score', 'N/A')}")
                        st.markdown(f"   - EPSS Score: {cve.get('epss_score', 'N/A')}")
                        st.markdown(f"   - KEV Flag: {'🟢 YES (Known Exploited)' if cve.get('kev_flag') else '⚪ No'}")
                        st.markdown(f"   - Severity: {cve.get('severity', 'N/A')}")
                        st.markdown(f"   - Technologies: {', '.join(cve.get('technologies', []))}")
            
            # Agent 3 Results - Show actual steps in chat
            if "agent3_result" in results:
                agent3_result = results['agent3_result']
                steps = agent3_result.get('remediation_steps', [])
                cve_id = agent3_result.get('cve_id', 'N/A')
                
                st.markdown("---")
                st.markdown("### 🛠️ Agent 3: Remediation Guide")
                st.markdown(f"**Target CVE:** {cve_id}")
                st.markdown(f"**Total Steps Generated:** {len(steps)}")
                st.markdown("\n**Step-by-Step Remediation Instructions:**\n")
                
                if steps:
                    for i, step in enumerate(steps, 1):
                        st.markdown(f"**Step {i}:** {step}")
                else:
                    st.markdown("No remediation steps available.")

# Chat input
if prompt := st.chat_input("Ask about bugs, risks, or fixes..."):
    # Add user message
    st.session_state.messages.append({"role": "user", "content": prompt})
    
    # Display user message
    with st.chat_message("user"):
        st.markdown(prompt)
    
    # Check if agents are initialized
    if not st.session_state.agents_initialized or not st.session_state.agent1:
        with st.chat_message("assistant"):
            st.error("Agents not initialized. Please refresh the page.")
    else:
        with st.chat_message("assistant"):
            try:
                # Step 1: Detect intent
                intent = detect_intent(prompt)
                
                # Step 2: Planner Agent - Plan which agents to run
                plan = planner_agent(prompt, intent)
                
                # Check if query is vague
                if plan['is_vague']:
                    # Show clarification message
                    clarification = plan['vague_info']['clarification_message']
                    st.markdown(clarification)
                    st.session_state.messages.append({
                        "role": "assistant",
                        "content": clarification
                    })
                    st.stop()
                
                # Check if specific CVE ID is mentioned
                if plan.get('cve_id'):
                    # User mentioned a specific CVE ID - search for it directly
                    cve_id = plan['cve_id']
                    found_cve = search_cve_by_id(cve_id)
                    
                    if found_cve:
                        # Found the specific CVE - use it directly
                        if intent == 'remediation':
                            # Provide fixes for this specific CVE
                            with st.spinner(f"🛠️ Generating remediation steps for {cve_id}..."):
                                agent3_result = st.session_state.agent3.process(found_cve)
                                
                                response_parts = []
                                response_parts.append(f"✅ **Remediation Guide for {cve_id}**\n\n")
                                response_parts.append(f"**Severity:** {found_cve.get('severity', 'N/A')}")
                                response_parts.append(f"**CVSS v3:** {found_cve.get('cvss_v3_score', 'N/A')}")
                                response_parts.append(f"**Technologies:** {', '.join(found_cve.get('technologies', []))}\n\n")
                                response_parts.append("**Step-by-Step Remediation Instructions:**\n\n")
                                
                                for i, step in enumerate(agent3_result.get('remediation_steps', []), 1):
                                    response_parts.append(f"**Step {i}:** {step}\n")
                                
                                response = "\n".join(response_parts)
                                agent_results = {'agent3_result': agent3_result}
                                st.markdown(response)
                                st.session_state.messages.append({
                                    "role": "assistant",
                                    "content": response,
                                    "agent_results": agent_results
                                })
                                st.stop()
                        else:
                            # For other intents, just show CVE info
                            response_parts = []
                            response_parts.append(f"✅ **Found CVE: {cve_id}**\n\n")
                            response_parts.append(f"**Severity:** {found_cve.get('severity', 'N/A')}")
                            response_parts.append(f"**CVSS v3:** {found_cve.get('cvss_v3_score', 'N/A')}")
                            response_parts.append(f"**Technologies:** {', '.join(found_cve.get('technologies', []))}")
                            response_parts.append(f"**Description:** {found_cve.get('description', 'N/A')}\n\n")
                            response_parts.append("💡 *Ask me to provide fixes for this CVE or assess its risk level.*")
                            response = "\n".join(response_parts)
                            agent_results = {'agent1_result': {'cves': [found_cve], 'count': 1}}
                            st.markdown(response)
                            st.session_state.messages.append({
                                "role": "assistant",
                                "content": response,
                                "agent_results": agent_results
                            })
                            st.stop()
                    else:
                        # CVE ID not found in database
                        response = f"❌ CVE {cve_id} not found in the database. Please check the CVE ID and try again."
                        st.markdown(response)
                        st.session_state.messages.append({
                            "role": "assistant",
                            "content": response
                        })
                        st.stop()
                
                # Show planner decision
                tech_display = ', '.join(plan['tech_keywords']) if plan['tech_keywords'] else 'None detected'
                st.caption(f"🔍 Intent: {intent} | Technology: {tech_display}")
                if plan['reason']:
                    st.caption(f"📋 Plan: {plan['reason']}")
                
                agent_results = {}
                response_parts = []
                
                # Step 3: Execute plan - Run Agent 1 if needed
                if plan['need_agent1']:
                    with st.spinner("🔍 Agent 1: Searching for relevant CVEs..."):
                        # Use the technology from query if available
                        query_for_agent1 = prompt
                        if plan['tech_keywords']:
                            # Enhance query with technology
                            tech_list = ', '.join(plan['tech_keywords'])
                            query_for_agent1 = f"{tech_list} {prompt}"
                        
                        agent1_result = st.session_state.agent1.process(query_for_agent1, top_k=10, strict_filter=True)
                        
                        if not agent1_result['cves']:
                            response = f"❌ No CVEs found for {tech_display if tech_display != 'None detected' else 'your tech stack'}. Please try mentioning specific technologies like Python, Kafka, Node.js, etc."
                            agent_results = {}
                            st.markdown(response)
                            st.session_state.messages.append({
                                "role": "assistant",
                                "content": response
                            })
                            st.stop()
                        else:
                            # Filter CVEs to match technology if specified
                            if plan['tech_keywords']:
                                filtered_cves = []
                                tech_keywords_lower = [kw.lower() for kw in plan['tech_keywords']]
                                for cve in agent1_result['cves']:
                                    cve_techs = [t.lower() for t in cve.get('technologies', [])]
                                    if any(tech_kw in ' '.join(cve_techs) or any(tech_kw in ct for ct in cve_techs) for tech_kw in tech_keywords_lower):
                                        filtered_cves.append(cve)
                                
                                if filtered_cves:
                                    agent1_result['cves'] = filtered_cves
                                    agent1_result['count'] = len(filtered_cves)
                                else:
                                    response = f"❌ No CVEs found matching {tech_display}. Please try a different technology."
                                    agent_results = {}
                                    st.markdown(response)
                                    st.session_state.messages.append({
                                        "role": "assistant",
                                        "content": response
                                    })
                                    st.stop()
                            
                            st.session_state.last_cves = agent1_result['cves']
                            agent_results['agent1_result'] = agent1_result
                            
                            if not plan['need_agent2'] and not plan['need_agent3']:
                                # Only Agent 1 needed - return CVE list
                                response_parts.append(f"✅ **Found {agent1_result['count']} relevant CVEs**\n\n")
                                response_parts.append(f"**Tech Stack:** {', '.join(plan['tech_keywords']) if plan['tech_keywords'] else agent1_result.get('tech_stack', 'N/A')}\n\n")
                                response_parts.append("**Relevant Vulnerabilities:**\n\n")
                                
                                for i, cve in enumerate(agent1_result['cves'][:10], 1):
                                    response_parts.append(f"**{i}. {cve['cve_id']}** - {cve.get('severity', 'N/A')}")
                                    response_parts.append(f"   - CVSS v3: {cve.get('cvss_v3_score', 'N/A')}")
                                    response_parts.append(f"   - Technologies: {', '.join(cve.get('technologies', []))}")
                                    response_parts.append(f"   - Description: {cve.get('description', '')[:200]}...\n")
                                
                                response_parts.append("\n💡 *You can now ask: 'What are the risk levels?' or 'Can you provide fixes?'*")
                
                # Step 4: Execute plan - Run Agent 2 if needed
                if plan['need_agent2']:
                    cves_to_assess = st.session_state.last_cves
                    
                    # Filter to technology if specified
                    if plan['tech_keywords'] and cves_to_assess:
                        tech_keywords_lower = [kw.lower() for kw in plan['tech_keywords']]
                        filtered_cves = []
                        for cve in cves_to_assess:
                            cve_techs = [t.lower() for t in cve.get('technologies', [])]
                            if any(tech_kw in ' '.join(cve_techs) or any(tech_kw in ct for ct in cve_techs) for tech_kw in tech_keywords_lower):
                                filtered_cves.append(cve)
                        if filtered_cves:
                            cves_to_assess = filtered_cves
                    
                    if not cves_to_assess:
                        response = "❌ No CVEs available for risk assessment."
                        agent_results = {}
                        st.markdown(response)
                        st.session_state.messages.append({
                            "role": "assistant",
                            "content": response
                        })
                        st.stop()
                    
                    with st.spinner("📊 Agent 2: Analyzing risk levels..."):
                        agent2_result = st.session_state.agent2.process(cves_to_assess)
                        st.session_state.last_prioritized = agent2_result['prioritized_cves']
                        agent_results['agent2_result'] = agent2_result
                        
                        if not plan['need_agent3']:
                            # Only Agent 2 needed - return prioritization
                            response_parts.append(f"✅ **Risk Assessment Complete**\n\n")
                            response_parts.append(f"**Prioritized {len(agent2_result['prioritized_cves'])} CVEs by Risk:**\n\n")
                            
                            for cve in agent2_result['prioritized_cves'][:5]:
                                response_parts.append(f"**Rank {cve['rank']}: {cve['cve_id']}** - **{cve.get('priority', 'N/A')} Priority**")
                                response_parts.append(f"   - Risk Score: {cve.get('risk_score', 0):.4f}")
                                response_parts.append(f"   - CVSS v3: {cve.get('cvss_v3_score', 'N/A')}")
                                response_parts.append(f"   - EPSS: {cve.get('epss_score', 'N/A')}")
                                response_parts.append(f"   - KEV Flag: {'🟢 YES (Known Exploited)' if cve.get('kev_flag') else '⚪ No'}")
                                response_parts.append(f"   - Severity: {cve.get('severity', 'N/A')}")
                                response_parts.append(f"   - Technologies: {', '.join(cve.get('technologies', []))}\n")
                            
                            response_parts.append("\n💡 *You can now ask: 'Can you provide the fix?' or 'What are the remediation steps?'*")
                
                # Step 5: Execute plan - Run Agent 3 if needed
                if plan['need_agent3']:
                    prioritized_to_use = st.session_state.last_prioritized
                    
                    # Filter to technology if specified
                    if plan['tech_keywords'] and prioritized_to_use:
                        tech_keywords_lower = [kw.lower() for kw in plan['tech_keywords']]
                        filtered_prioritized = []
                        for cve in prioritized_to_use:
                            cve_techs = [t.lower() for t in cve.get('technologies', [])]
                            if any(tech_kw in ' '.join(cve_techs) or any(tech_kw in ct for ct in cve_techs) for tech_kw in tech_keywords_lower):
                                filtered_prioritized.append(cve)
                        if filtered_prioritized:
                            prioritized_to_use = filtered_prioritized
                    
                    top_cve = prioritized_to_use[0] if prioritized_to_use else None
                    
                    if not top_cve:
                        response = "❌ No prioritized CVE found for remediation."
                        agent_results = {}
                        st.markdown(response)
                        st.session_state.messages.append({
                            "role": "assistant",
                            "content": response
                        })
                        st.stop()
                    
                    with st.spinner("🛠️ Agent 3: Generating remediation steps..."):
                        agent3_result = st.session_state.agent3.process(top_cve)
                        agent_results['agent3_result'] = agent3_result
                        
                        response_parts.append(f"✅ **Remediation Guide for {agent3_result.get('cve_id', 'N/A')}**\n\n")
                        response_parts.append(f"**Severity:** {top_cve.get('severity', 'N/A')}")
                        response_parts.append(f"**CVSS v3:** {top_cve.get('cvss_v3_score', 'N/A')}")
                        response_parts.append(f"**Priority:** {top_cve.get('priority', 'N/A')}")
                        response_parts.append(f"**Risk Score:** {top_cve.get('risk_score', 0):.4f}")
                        response_parts.append(f"**Technologies:** {', '.join(top_cve.get('technologies', []))}\n\n")
                        response_parts.append("**Step-by-Step Remediation Instructions:**\n\n")
                        
                        for i, step in enumerate(agent3_result.get('remediation_steps', []), 1):
                            response_parts.append(f"**Step {i}:** {step}\n")
                
                # If no plan executed, show default message
                if not response_parts:
                    response = "I can help you with:\n- Finding vulnerabilities in your tech stack\n- Assessing risk levels\n- Providing remediation steps\n\nWhat would you like to know?"
                else:
                    response = "\n".join(response_parts)
                
                st.markdown(response)
                
                # Add assistant message
                st.session_state.messages.append({
                    "role": "assistant",
                    "content": response,
                    "agent_results": agent_results
                })
                
            except Exception as e:
                error_msg = f"❌ Error: {str(e)}"
                st.error(error_msg)
                st.session_state.messages.append({
                    "role": "assistant",
                    "content": error_msg
                })

# Display agent status in footer
st.markdown("---")
col1, col2, col3 = st.columns(3)

with col1:
    if st.session_state.agents_initialized:
        st.success("✅ Agent 1: Ready")
    else:
        st.error("❌ Agent 1: Not Ready")

with col2:
    if st.session_state.agents_initialized:
        st.success("✅ Agent 2: Ready")
    else:
        st.error("❌ Agent 2: Not Ready")

with col3:
    if st.session_state.agents_initialized:
        st.success("✅ Agent 3: Ready")
    else:
        st.error("❌ Agent 3: Not Ready")

