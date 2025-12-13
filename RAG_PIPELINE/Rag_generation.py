import sys
import os
import re
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import os
from dotenv import load_dotenv
import pandas as pd

# Load environment variables
load_dotenv()

def format_cves_for_llm(cves_df):
    """
    Format retrieved CVEs as context for LLM.
    
    Args:
        cves_df: DataFrame with CVE results from vector search
    
    Returns:
        Formatted string with CVE information
    """
    if cves_df is None or len(cves_df) == 0:
        return "No CVEs found."
    
    formatted_cves = []
    for idx, row in cves_df.iterrows():
        # Start with core CVE information
        cve_info = f"""
CVE ID: {row['cve_id']}
Title: {row['title']}
"""
        
        # Add all available fields dynamically (excluding similarity_score, embedding_vector, and rn)
        exclude_cols = {'similarity_score', 'embedding_vector', 'rn', 'cve_id', 'title'}
        
        for col in cves_df.columns:
            col_lower = col.lower()
            if col_lower not in exclude_cols and pd.notna(row[col]):
                value = row[col]
                
                # Format specific columns
                if col_lower == 'cvss_score':
                    severity = row.get('cvss_severity', '')
                    if pd.notna(severity):
                        cve_info += f"CVSS Score: {value} ({severity})\n"
                    else:
                        cve_info += f"CVSS Score: {value}\n"
                elif col_lower == 'description':
                    desc = str(value)
                    if len(desc) > 500:
                        cve_info += f"Description: {desc[:500]}...\n"
                    else:
                        cve_info += f"Description: {desc}\n"
                elif col_lower == 'combined_text':
                    # Skip COMBINED_TEXT as it's already embedded, but include if user wants
                    pass
                else:
                    # Format column name nicely (replace underscores with spaces, title case)
                    col_name = col.replace('_', ' ').title()
                    cve_info += f"{col_name}: {value}\n"
        
        # Add similarity score at the end
        if 'similarity_score' in cves_df.columns:
            cve_info += f"Similarity Score: {row['similarity_score']:.4f}\n"
        
        formatted_cves.append(cve_info)
    
    return "\n---\n".join(formatted_cves)

def generate_answer_openai(user_question, cves_df, model="gpt-4o-mini", conversation_history=None):
    """
    Generate answer using OpenAI API.
    
    Args:
        user_question: User's original question
        cves_df: DataFrame with retrieved CVEs
        model: OpenAI model to use (default: gpt-4o-mini)
        conversation_history: List of previous Q&A pairs [{"question": "...", "answer": "..."}]
    
    Returns:
        Generated answer string
    """
    try:
        from openai import OpenAI
        
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY not found in environment variables")
        
        client = OpenAI(api_key=api_key)
        
        # Format CVEs as context
        cves_context = format_cves_for_llm(cves_df)
        
        # Detect if user asked for a specific number of CVEs
        question_lower = user_question.lower()
        top_n_match = re.search(r'top\s+(\d+)|(\d+)\s+(highest|lowest|most|least)', question_lower)
        requested_count = None
        if top_n_match:
            requested_count = int(top_n_match.group(1) or top_n_match.group(2))
        
        # Determine if we should list all CVEs
        num_cves_retrieved = len(cves_df) if cves_df is not None else 0
        should_list_all = requested_count is not None or "list" in question_lower or "show" in question_lower or "all" in question_lower
        
        # Build messages with conversation history
        messages = [
            {"role": "system", "content": "You are a helpful cybersecurity expert. Answer questions directly - provide the information specifically requested. If asked for a specific number of items, list ALL of them."}
        ]
        
        # Add conversation history if available
        if conversation_history:
            for item in conversation_history:
                # Safely access keys - handle both "question"/"answer" and "input"/"output" formats
                if isinstance(item, dict):
                    question = item.get("question") or item.get("input")
                    answer = item.get("answer") or item.get("output")
                    
                    # Only add if both question and answer exist
                    if question and answer:
                        messages.append({"role": "user", "content": str(question)})
                        messages.append({"role": "assistant", "content": str(answer)})
        
        # Build prompt based on whether we need to list all CVEs
        if should_list_all and num_cves_retrieved > 0:
            list_instruction = f"IMPORTANT: The user asked for {requested_count} CVEs. List ALL {num_cves_retrieved} CVEs from the retrieved set. Do NOT summarize or skip any."
        else:
            list_instruction = "Answer directly and concisely."
        
        # Add current question with CVE context
        current_prompt = f"""Based on the following CVEs retrieved from a database, answer the user's question.

Retrieved CVEs ({num_cves_retrieved} total):
{cves_context}

User Question: {user_question}

CRITICAL INSTRUCTIONS:
{list_instruction}
- Answer ONLY what is specifically asked in the question
- If asked about a specific field (product, vendor, EPSS score, CVSS score, etc.), provide ONLY that information
- If asked for "top N" or a specific number, list ALL N CVEs - do NOT summarize or skip any
- If multiple CVEs match, list the requested information for EACH CVE
- If the user asks "what is the product", answer with just the product name(s)
- If the user asks "what is the vendor", answer with just the vendor name(s)
- If the user asks "what is the EPSS score", answer with just the score(s)
- If the user asks a follow-up question, use context from previous answers
- If no relevant CVEs are found, say so clearly

Answer:"""
        
        messages.append({"role": "user", "content": current_prompt})
        
        # Calculate max_tokens based on number of CVEs (more CVEs = more tokens needed)
        base_tokens = 1000
        tokens_per_cve = 150  # Approximate tokens per CVE in response
        calculated_max_tokens = base_tokens + (num_cves_retrieved * tokens_per_cve)
        max_tokens = min(calculated_max_tokens, 4000)  # Cap at 4000 tokens
        
        # Call OpenAI API
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=0.3,  # Lower temperature for more factual responses
            max_tokens=max_tokens
        )
        
        return response.choices[0].message.content
        
    except ImportError:
        raise ImportError("OpenAI package not installed. Run: pip install openai")
    except Exception as e:
        raise Exception(f"OpenAI API error: {e}")

def generate_answer_anthropic(user_question, cves_df, model="claude-3-haiku-20240307", conversation_history=None):
    """
    Generate answer using Anthropic API.
    
    Args:
        user_question: User's original question
        cves_df: DataFrame with retrieved CVEs
        model: Anthropic model to use (default: claude-3-haiku-20240307)
        conversation_history: List of previous Q&A pairs [{"question": "...", "answer": "..."}]
    
    Returns:
        Generated answer string
    """
    try:
        from anthropic import Anthropic
        
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY not found in environment variables")
        
        client = Anthropic(api_key=api_key)
        
        # Format CVEs as context
        cves_context = format_cves_for_llm(cves_df)
        
        # Detect if user asked for a specific number of CVEs
        question_lower = user_question.lower()
        top_n_match = re.search(r'top\s+(\d+)|(\d+)\s+(highest|lowest|most|least)', question_lower)
        requested_count = None
        if top_n_match:
            requested_count = int(top_n_match.group(1) or top_n_match.group(2))
        
        # Determine if we should list all CVEs
        num_cves_retrieved = len(cves_df) if cves_df is not None else 0
        should_list_all = requested_count is not None or "list" in question_lower or "show" in question_lower or "all" in question_lower
        
        # Build conversation context
        conversation_text = ""
        if conversation_history:
            conversation_text = "\n\nPrevious conversation:\n"
            for item in conversation_history:
                # Safely access keys - handle both "question"/"answer" and "input"/"output" formats
                if isinstance(item, dict):
                    question = item.get("question") or item.get("input")
                    answer = item.get("answer") or item.get("output")
                    if question and answer:
                        conversation_text += f"Q: {str(question)}\nA: {str(answer)}\n\n"
        
        # Build prompt based on whether we need to list all CVEs
        if should_list_all and num_cves_retrieved > 0:
            list_instruction = f"IMPORTANT: The user asked for {requested_count} CVEs. List ALL {num_cves_retrieved} CVEs from the retrieved set. Do NOT summarize or skip any."
        else:
            list_instruction = "Answer directly and concisely."
        
        # Create prompt
        prompt = f"""You are a cybersecurity expert. Based on the following CVEs retrieved from a database, answer the user's question.

{conversation_text}Retrieved CVEs ({num_cves_retrieved} total):
{cves_context}

User Question: {user_question}

CRITICAL INSTRUCTIONS:
{list_instruction}
- Answer ONLY what is specifically asked in the question
- If asked about a specific field (product, vendor, EPSS score, CVSS score, etc.), provide ONLY that information
- If asked for "top N" or a specific number, list ALL N CVEs - do NOT summarize or skip any
- If multiple CVEs match, list the requested information for EACH CVE
- If the user asks "what is the product", answer with just the product name(s)
- If the user asks "what is the vendor", answer with just the vendor name(s)
- If the user asks "what is the EPSS score", answer with just the score(s)
- If the user asks a follow-up question, use context from previous answers
- If no relevant CVEs are found, say so clearly

Answer:"""
        
        # Build messages for Anthropic
        messages = []
        if conversation_history:
            for item in conversation_history:
                # Safely access keys - handle both "question"/"answer" and "input"/"output" formats
                if isinstance(item, dict):
                    question = item.get("question") or item.get("input")
                    answer = item.get("answer") or item.get("output")
                    
                    # Only add if both question and answer exist
                    if question and answer:
                        messages.append({"role": "user", "content": str(question)})
                        messages.append({"role": "assistant", "content": str(answer)})
        
        messages.append({"role": "user", "content": prompt})
        
        # Calculate max_tokens based on number of CVEs
        base_tokens = 1000
        tokens_per_cve = 150
        calculated_max_tokens = base_tokens + (num_cves_retrieved * tokens_per_cve)
        max_tokens = min(calculated_max_tokens, 4000)  # Cap at 4000 tokens
        
        # Call Anthropic API
        message = client.messages.create(
            model=model,
            max_tokens=max_tokens,
            temperature=0.3,
            messages=messages
        )
        
        return message.content[0].text
        
    except ImportError:
        raise ImportError("Anthropic package not installed. Run: pip install anthropic")
    except Exception as e:
        raise Exception(f"Anthropic API error: {e}")

def generate_answer(user_question, cves_df, provider="openai", model=None, conversation_history=None):
    """
    Generate answer using specified LLM provider.
    
    Args:
        user_question: User's original question
        cves_df: DataFrame with retrieved CVEs
        provider: "openai" or "anthropic" (default: "openai")
        model: Model name (optional, uses defaults if not provided)
        conversation_history: List of previous Q&A pairs [{"question": "...", "answer": "..."}]
    
    Returns:
        Generated answer string
    """
    if provider.lower() == "openai":
        return generate_answer_openai(user_question, cves_df, model or "gpt-4o-mini", conversation_history)
    elif provider.lower() == "anthropic":
        return generate_answer_anthropic(user_question, cves_df, model or "claude-3-haiku-20240307", conversation_history)
    else:
        raise ValueError(f"Unknown provider: {provider}. Use 'openai' or 'anthropic'")