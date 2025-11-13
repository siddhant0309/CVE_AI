"""
Streamlit Conversational Chat UI for Multi-Agent CVE Analysis System
Agents run on-demand based on user questions
"""

import streamlit as st
import json
import re
from agent1_cve_retrieval import CVERetrievalAgent, collection, embedding_model, llm_client as llm_client_1
from agent2_risk_assessment import RiskAssessmentAgent
from agent3_remediation import RemediationAgent
from openai import OpenAI
import os
from dotenv import load_dotenv

load_dotenv()

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
if 'llm_client' not in st.session_state:
    st.session_state.llm_client = None

# Initialize LLM client for intent detection
try:
    api_key = os.getenv("OPENAI_API_KEY")
    if api_key and api_key.strip():
        st.session_state.llm_client = OpenAI(api_key=api_key)
        LLM_MODEL = "gpt-3.5-turbo"
    else:
        st.session_state.llm_client = None
except:
    st.session_state.llm_client = None

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

def detect_intent(user_message: str) -> str:
    """Detect user intent to determine which agent to use"""
    if not st.session_state.llm_client:
        # Fallback to keyword detection
        message_lower = user_message.lower()
        if any(word in message_lower for word in ['risk', 'priority', 'prioritize', 'severity', 'dangerous']):
            return 'risk_assessment'
        elif any(word in message_lower for word in ['fix', 'solution', 'remedy', 'patch', 'remediation', 'remediate']):
            return 'remediation'
        elif any(word in message_lower for word in ['bug', 'vulnerability', 'cve', 'security issue', 'find', 'help']):
            return 'cve_retrieval'
        return 'cve_retrieval'  # Default
    
    try:
        prompt = f"""Analyze the user's message and determine which agent should respond:
- "cve_retrieval": User is asking about finding bugs, vulnerabilities, CVEs, or tech stack issues
- "risk_assessment": User is asking about risk levels, priorities, severity, or danger levels
- "remediation": User is asking for fixes, solutions, patches, or remediation steps

User message: "{user_message}"

Respond with ONLY one word: cve_retrieval, risk_assessment, or remediation"""

        response = st.session_state.llm_client.chat.completions.create(
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

def extract_tech_stack_from_chat(messages: list) -> str:
    """Extract tech stack from conversation history"""
    for msg in reversed(messages):
        if msg['role'] == 'user':
            content = msg['content'].lower()
            # Look for tech stack mentions
            if any(tech in content for tech in ['python', 'java', 'react', 'postgresql', 'mongodb', 'node', 'docker', 'kubernetes']):
                return msg['content']
    return None

# Sidebar
with st.sidebar:
    st.title("🔒 CVE Analysis System")
    st.markdown("---")
    st.markdown("### Conversational Flow")
    st.markdown("""
    **Step 1:** Ask about bugs/vulnerabilities
    - Example: "I'm experiencing a bug, can you help?"
    
    **Step 2:** Ask about risk levels
    - Example: "What are the risk levels?"
    
    **Step 3:** Ask for fixes
    - Example: "Can you provide the fix?"
    """)
    st.markdown("---")
    
    if st.button("🗑️ Clear Chat History"):
        st.session_state.messages = []
        st.session_state.last_cves = None
        st.session_state.last_prioritized = None
        st.rerun()
    
    st.markdown("---")
    st.markdown("### Demo Tech Stacks")
    st.markdown("""
    Try these tech stacks:
    - Python 3.9
    - Kubernetes, PyTorch
    - React, Node.js, MongoDB
    - PostgreSQL, Apache
    - WordPress, Express
    """)

# Main title
st.title("🔒 CVE Multi-Agent Analysis System")
st.markdown("💬 Chat conversationally - Ask about bugs, risks, and fixes")

# Display chat history
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])
        
        # Display detailed results in chat
        if "agent_results" in message:
            results = message["agent_results"]
            
            # Agent 1 Results
            if "agent1_result" in results:
                agent1_result = results['agent1_result']
                st.markdown("---")
                st.markdown("### 🔍 Found CVEs:")
                for i, cve in enumerate(agent1_result.get('cves', [])[:10], 1):
                    st.markdown(f"**{i}. {cve['cve_id']}** - {cve.get('severity', 'N/A')}")
                    st.markdown(f"   - CVSS v3: {cve.get('cvss_v3_score', 'N/A')}")
                    st.markdown(f"   - Technologies: {', '.join(cve.get('technologies', []))}")
                    st.markdown(f"   - Description: {cve.get('description', '')[:150]}...")
                    st.markdown("")
            
            # Agent 2 Results
            if "agent2_result" in results:
                agent2_result = results['agent2_result']
                prioritized = agent2_result.get('prioritized_cves', [])
                
                st.markdown("---")
                st.markdown("### 📊 Risk Assessment Results:")
                for cve in prioritized[:5]:
                    st.markdown(f"**{cve['cve_id']}** - Priority: **{cve.get('priority', 'N/A')}**")
                    st.markdown(f"   - Risk Score: {cve.get('risk_score', 0):.4f}")
                    st.markdown(f"   - CVSS v3: {cve.get('cvss_v3_score', 'N/A')}")
                    st.markdown(f"   - KEV: {'🟢 YES' if cve.get('kev_flag') else '⚪ No'}")
                    st.markdown(f"   - EPSS: {cve.get('epss_score', 'N/A')}")
                    st.markdown("")
            
            # Agent 3 Results
            if "agent3_result" in results:
                agent3_result = results['agent3_result']
                steps = agent3_result.get('remediation_steps', [])
                
                st.markdown("---")
                st.markdown("### 🛠️ Remediation Steps:")
                for i, step in enumerate(steps, 1):
                    st.markdown(f"**Step {i}:** {step}")

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
                # Detect intent
                intent = detect_intent(prompt)
                
                if intent == 'cve_retrieval':
                    # Agent 1: CVE Retrieval
                    with st.spinner("🔍 Searching for relevant CVEs..."):
                        agent1_result = st.session_state.agent1.process(prompt, top_k=10)
                        
                        if not agent1_result['cves']:
                            response = "❌ No CVEs found for your tech stack. Please try mentioning specific technologies like Python, PostgreSQL, React, etc."
                            agent_results = {}
                        else:
                            st.session_state.last_cves = agent1_result['cves']
                            
                            response_parts = []
                            response_parts.append(f"✅ **Found {agent1_result['count']} relevant CVEs for your tech stack**\n\n")
                            response_parts.append(f"**Tech Stack:** {agent1_result.get('tech_stack', 'N/A')}\n\n")
                            response_parts.append("**Relevant Vulnerabilities:**\n\n")
                            
                            for i, cve in enumerate(agent1_result['cves'][:10], 1):
                                response_parts.append(f"**{i}. {cve['cve_id']}** - {cve.get('severity', 'N/A')}")
                                response_parts.append(f"   - CVSS v3: {cve.get('cvss_v3_score', 'N/A')}")
                                response_parts.append(f"   - Technologies: {', '.join(cve.get('technologies', []))}")
                                response_parts.append(f"   - Description: {cve.get('description', '')[:200]}...\n")
                            
                            response_parts.append("\n💡 *You can now ask: 'What are the risk levels?' or 'Can you provide fixes?'*")
                            
                            response = "\n".join(response_parts)
                            agent_results = {'agent1_result': agent1_result}
                    
                elif intent == 'risk_assessment':
                    # Agent 2: Risk Assessment
                    if not st.session_state.last_cves:
                        # Try to extract tech stack from conversation
                        tech_stack = extract_tech_stack_from_chat(st.session_state.messages)
                        if tech_stack:
                            with st.spinner("🔍 First, finding CVEs..."):
                                agent1_result = st.session_state.agent1.process(tech_stack, top_k=10)
                                st.session_state.last_cves = agent1_result['cves']
                        else:
                            response = "❌ No CVEs found yet. Please first ask about bugs or vulnerabilities in your tech stack."
                            agent_results = {}
                            st.markdown(response)
                            st.session_state.messages.append({
                                "role": "assistant",
                                "content": response
                            })
                            st.stop()
                    
                    with st.spinner("📊 Analyzing risk levels..."):
                        agent2_result = st.session_state.agent2.process(st.session_state.last_cves)
                        st.session_state.last_prioritized = agent2_result['prioritized_cves']
                        
                        response_parts = []
                        response_parts.append(f"✅ **Risk Assessment Complete**\n\n")
                        response_parts.append(f"**Prioritized {len(agent2_result['prioritized_cves'])} CVEs by Risk:**\n\n")
                        
                        for cve in agent2_result['prioritized_cves'][:5]:
                            response_parts.append(f"**Rank {cve['rank']}: {cve['cve_id']}** - **{cve.get('priority', 'N/A')} Priority**")
                            response_parts.append(f"   - Risk Score: {cve.get('risk_score', 0):.4f}")
                            response_parts.append(f"   - CVSS v3: {cve.get('cvss_v3_score', 'N/A')}")
                            response_parts.append(f"   - EPSS: {cve.get('epss_score', 'N/A')}")
                            response_parts.append(f"   - KEV Flag: {'🟢 YES (Known Exploited)' if cve.get('kev_flag') else '⚪ No'}")
                            response_parts.append(f"   - Severity: {cve.get('severity', 'N/A')}\n")
                        
                        response_parts.append("\n💡 *You can now ask: 'Can you provide the fix?' or 'What are the remediation steps?'*")
                        
                        response = "\n".join(response_parts)
                        agent_results = {'agent2_result': agent2_result}
                
                elif intent == 'remediation':
                    # Agent 3: Remediation
                    if not st.session_state.last_prioritized:
                        # Try to get prioritized CVEs first
                        if st.session_state.last_cves:
                            with st.spinner("📊 First, assessing risks..."):
                                agent2_result = st.session_state.agent2.process(st.session_state.last_cves)
                                st.session_state.last_prioritized = agent2_result['prioritized_cves']
                        else:
                            response = "❌ No CVEs analyzed yet. Please first ask about bugs in your tech stack."
                            agent_results = {}
                            st.markdown(response)
                            st.session_state.messages.append({
                                "role": "assistant",
                                "content": response
                            })
                            st.stop()
                    
                    top_cve = st.session_state.last_prioritized[0] if st.session_state.last_prioritized else None
                    
                    if not top_cve:
                        response = "❌ No prioritized CVE found. Please ask about risk levels first."
                        agent_results = {}
                    else:
                        with st.spinner("🛠️ Generating remediation steps..."):
                            agent3_result = st.session_state.agent3.process(top_cve)
                            
                            response_parts = []
                            response_parts.append(f"✅ **Remediation Guide for {agent3_result.get('cve_id', 'N/A')}**\n\n")
                            response_parts.append(f"**Severity:** {top_cve.get('severity', 'N/A')}")
                            response_parts.append(f"**CVSS v3:** {top_cve.get('cvss_v3_score', 'N/A')}")
                            response_parts.append(f"**Priority:** {top_cve.get('priority', 'N/A')}\n\n")
                            response_parts.append("**Step-by-Step Remediation Instructions:**\n\n")
                            
                            for i, step in enumerate(agent3_result.get('remediation_steps', []), 1):
                                response_parts.append(f"**Step {i}:** {step}\n")
                            
                            response = "\n".join(response_parts)
                            agent_results = {'agent3_result': agent3_result}
                
                else:
                    response = "I can help you with:\n- Finding vulnerabilities in your tech stack\n- Assessing risk levels\n- Providing remediation steps\n\nWhat would you like to know?"
                    agent_results = {}
                
                st.markdown(response)
                
                # Add assistant message
                st.session_state.messages.append({
                    "role": "assistant",
                    "content": response,
                    "agent_results": agent_results if 'agent_results' in locals() else {}
                })
                
            except Exception as e:
                error_msg = f"❌ Error: {str(e)}"
                st.error(error_msg)
                st.session_state.messages.append({
                    "role": "assistant",
                    "content": error_msg
                })

# Footer
st.markdown("---")
col1, col2, col3 = st.columns(3)
with col1:
    status = "✅ Ready" if st.session_state.agents_initialized else "❌ Not Ready"
    st.markdown(f"**Agent 1:** {status}")
with col2:
    status = "✅ Ready" if st.session_state.agents_initialized else "❌ Not Ready"
    st.markdown(f"**Agent 2:** {status}")
with col3:
    status = "✅ Ready" if st.session_state.agents_initialized else "❌ Not Ready"
    st.markdown(f"**Agent 3:** {status}")

