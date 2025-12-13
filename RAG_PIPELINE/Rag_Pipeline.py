import sys
import os
import re
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from RAG_PIPELINE.vector_search import search_similar_cves, search_similar_cves_hybrid, parse_query_intent, search_similar_cves_multi_tech
from RAG_PIPELINE.Rag_generation import generate_answer
import pandas as pd

def extract_cve_ids(text):
    """
    Extract CVE IDs from text using regex.
    
    Args:
        text: Text to search for CVE IDs
    
    Returns:
        List of CVE IDs found (e.g., ['CVE-2025-9074', 'CVE-2024-1234'])
    """
    # Pattern: CVE-YYYY-NNNNN (4 digits, dash, 4-7 digits)
    cve_pattern = r'CVE-\d{4}-\d{4,7}'
    cve_ids = re.findall(cve_pattern, text, re.IGNORECASE)
    # Remove duplicates and return unique list
    return list(set(cve_ids))

def is_explicit_followup(question):
    """
    Check if question explicitly references previous context.
    
    Args:
        question: User's question
    
    Returns:
        bool: True if question is an explicit follow-up
    """
    question_lower = question.lower()
    
    # Explicit follow-up phrases
    followup_phrases = [
        "tell me more", "more about", "what about", "that one", "the one",
        "you mentioned", "you said", "from above", "from previous",
        "from the list", "which one", "the first", "the second",
        "the last", "that cve", "this cve", "those cves", "these cves",
        "about it", "about that", "regarding that", "concerning that"
    ]
    
    return any(phrase in question_lower for phrase in followup_phrases)

def extract_topic_from_question(question):
    """
    Extract technology/topic from a question to detect if it's about a different topic.
    Returns the first technology found (for backward compatibility).
    
    Args:
        question: User's question
    
    Returns:
        str: Extracted topic/technology (e.g., "python", "jenkins", "apache") or None
    """
    from RAG_PIPELINE.vector_search import extract_all_technologies
    all_techs = extract_all_technologies(question)
    return all_techs[0] if all_techs else None

def filter_cves_by_id(cves_df, cve_ids):
    """
    Filter CVEs DataFrame to only include specified CVE IDs.
    
    Args:
        cves_df: DataFrame with CVEs
        cve_ids: List of CVE IDs to filter to
    
    Returns:
        Filtered DataFrame
    """
    if cves_df is None or len(cves_df) == 0 or not cve_ids:
        return cves_df
    
    # Filter to CVEs that match the extracted IDs
    filtered = cves_df[cves_df['cve_id'].isin(cve_ids)]
    return filtered if len(filtered) > 0 else cves_df

def rag_query(user_question, top_k=10, provider="openai", model=None, conversation_history=None, previous_cves=None, previous_topic=None, similarity_threshold=0.55):
    """
    Complete RAG pipeline: Vector Search + LLM Generation.
    
    Args:
        user_question: User's question
        top_k: Number of CVEs to retrieve (default: 10). Will use 15 for keyword matching.
        provider: "openai" or "anthropic" (default: "openai")
        model: Model name (optional)
        conversation_history: List of previous Q&A pairs [{"question": "...", "answer": "..."}]
        previous_cves: DataFrame with previous CVEs (for follow-up questions)
        previous_topic: Topic from previous question (to detect topic changes)
        similarity_threshold: Minimum similarity score (0.0-1.0). Default: 0.55
    
    Returns:
        dict with 'answer', 'retrieved_cves', and 'detected_topic'
    """
    print("="*80)
    print("RAG PIPELINE")
    print("="*80)
    print(f"\nQuestion: {user_question}\n")
    
    # Extract topic from current question (for tracking, not for follow-up detection)
    current_topic = extract_topic_from_question(user_question)
    
    # Step 1: Vector Search (Retrieval) - Only use previous CVEs for explicit follow-ups
    is_followup = is_explicit_followup(user_question)
    
    should_use_previous = (
        is_followup and
        previous_cves is not None and 
        len(previous_cves) > 0
    )
    
    if should_use_previous:
        print("Step 1: Using previous CVEs (explicit follow-up detected)...")
        retrieved_cves = previous_cves
        print(f"[OK] Using {len(retrieved_cves)} CVEs from previous query\n")
    else:
        # Always do a new search for independent questions
        if current_topic:
            print(f"[INFO] Detected topic: {current_topic}")
        print("Step 1: Retrieving relevant CVEs...")
        
        # Check if query needs hybrid search (SQL-style operations) or multi-tech search
        intent = parse_query_intent(user_question)
        technologies = intent.get('technologies', [])
        
        # Auto-detect top_k from question, use provided top_k as fallback
        detected_limit = intent['limit'] if intent['limit'] else top_k
        
        # Check if multiple technologies are mentioned (always check this first)
        if technologies and len(technologies) > 1:
            print(f"[INFO] Detected multiple technologies: {', '.join(technologies)}")
            # Search each technology separately and combine
            if detected_limit is not None:
                top_k_per_tech = max(5, detected_limit // len(technologies))  # Distribute evenly
            else:
                top_k_per_tech = None  # Get all results for each tech
            retrieved_cves = search_similar_cves_multi_tech(technologies, top_k_per_tech=top_k_per_tech, query_text=user_question, similarity_threshold=similarity_threshold)
        elif intent['is_sql_style']:
            print(f"[INFO] Detected SQL-style query - using hybrid search")
            retrieved_cves = search_similar_cves_hybrid(user_question, top_k=detected_limit, similarity_threshold=similarity_threshold)
        else:
            # Regular semantic search (single technology or no specific technology)
            # Use transformed semantic_query if technology was detected, otherwise use original query
            # This makes it work for ANY phrasing: "can you give me", "show me", "what are", etc.
            search_query = intent.get('semantic_query') if intent.get('semantic_query') else user_question
            retrieved_cves = search_similar_cves(search_query, top_k=15, similarity_threshold=similarity_threshold)
        
        if retrieved_cves is None or len(retrieved_cves) == 0:
            return {
                "answer": "I couldn't find any relevant CVEs for your question.",
                "retrieved_cves": None
            }
        
        print(f"[OK] Retrieved {len(retrieved_cves)} CVEs\n")
    
    # Step 2: LLM Generation
    print("Step 2: Generating answer using LLM...")
    try:
        answer = generate_answer(user_question, retrieved_cves, provider=provider, model=model, conversation_history=conversation_history)
        print("[OK] Answer generated\n")
        
        # Step 3: Extract CVE IDs from answer and filter if specific CVE was mentioned
        # This helps with follow-up questions - if LLM mentions a specific CVE, use only that
        extracted_cve_ids = extract_cve_ids(answer)
        
        # Check if question is asking to select/identify a specific CVE
        question_lower = user_question.lower()
        is_selection_question = any(phrase in question_lower for phrase in [
            "most severe", "highest", "worst", "most critical", "return the one", 
            "which one", "first one", "second one", "last one", "the one", "that one"
        ])
        
        # If a specific CVE was mentioned and question was about selecting one, filter to it
        if extracted_cve_ids and is_selection_question and len(extracted_cve_ids) == 1:
            filtered_cves = filter_cves_by_id(retrieved_cves, extracted_cve_ids)
            if len(filtered_cves) < len(retrieved_cves):
                print(f"[INFO] Auto-filtered to CVE: {extracted_cve_ids[0]} (mentioned in answer)\n")
                retrieved_cves = filtered_cves
        elif extracted_cve_ids and len(extracted_cve_ids) == 1 and len(retrieved_cves) > 1:
            # Even if not explicitly a selection question, if only one CVE is mentioned, use it
            # This helps with follow-ups like "Tell me more about it"
            filtered_cves = filter_cves_by_id(retrieved_cves, extracted_cve_ids)
            if len(filtered_cves) == 1:
                print(f"[INFO] Auto-filtered to mentioned CVE: {extracted_cve_ids[0]}\n")
                retrieved_cves = filtered_cves
        
        return {
            "answer": answer,
            "retrieved_cves": retrieved_cves,
            "detected_topic": current_topic
        }
    except Exception as e:
        print(f"[ERROR] Generation failed: {e}\n")
        return {
            "answer": f"Error generating answer: {e}",
            "retrieved_cves": retrieved_cves
        }

if __name__ == "__main__":
    # Test the RAG pipeline
    question = "What Apache vulnerabilities exist?"
    
    result = rag_query(
        question, 
        top_k=5, 
        provider="openai"  # or "anthropic"
    )
    
    print("="*80)
    print("ANSWER:")
    print("="*80)
    print(result["answer"])
    print("\n" + "="*80)
    print("Retrieved CVEs:")
    print("="*80)
    if result["retrieved_cves"] is not None:
        print(result["retrieved_cves"][['cve_id', 'title', 'similarity_score', 'cvss_score']].to_string())

