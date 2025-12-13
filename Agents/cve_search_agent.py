import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from RAG_PIPELINE.Rag_Pipeline import rag_query
from RAG_PIPELINE.vector_search import search_similar_cves
import pandas as pd

class CVESearchAgent:
    """
    Agent that searches for CVEs in the database using RAG (Retrieval-Augmented Generation).
    Can search for any CVE query and provides intelligent answers using LLM.
    """
    
    def __init__(self, top_k=10, provider="openai", model=None):
        """
        Initialize the CVE Search Agent.
        
        Args:
            top_k: Number of CVEs to retrieve per search (default: 5)
            provider: LLM provider - "openai" or "anthropic" (default: "openai")
            model: Model name (optional, uses defaults if not provided)
        """
        self.top_k = top_k
        self.provider = provider
        self.model = model
        self.conversation_history = []  # Individual agent memory
        self.previous_cves = None  # Store CVEs from last search for follow-ups
        self.previous_topic = None  # Store topic from last question to detect topic changes
    
    def get_cve_by_id(self, cve_id):
        """
        Query Snowflake directly for a specific CVE-ID.
        
        Args:
            cve_id: CVE identifier (e.g., "CVE-2024-1234") or text containing CVE-ID
        
        Returns:
            pandas DataFrame with CVE details, or None if not found
        """
        try:
            from patchpath.config.snowflake_config import get_snowflake_session
            import re
            
            # Extract CVE-ID from text if needed
            if not cve_id.upper().startswith('CVE-') or not re.match(r'^CVE-\d{4}-\d{4,7}$', cve_id.upper()):
                cve_pattern = r'CVE-\d{4}-\d{4,7}'
                matches = re.findall(cve_pattern, cve_id.upper())
                if matches:
                    cve_id = matches[0]
                else:
                    print(f"[WARNING] Could not extract valid CVE-ID from: {cve_id}")
                    return None
            
            # Normalize CVE-ID (uppercase)
            cve_id = cve_id.strip().upper()
            
            session = get_snowflake_session()
            
            # Query for specific CVE-ID
            query = f"""
            SELECT *
            FROM TESTCVE.CVE.VULN_GOLD_FINAL
            WHERE CVE_ID = '{cve_id}'
            """
            
            results = session.sql(query)
            df = results.to_pandas()
            
            # Normalize column names to lowercase
            df.columns = df.columns.str.lower()
            
            session.close()
            
            if len(df) == 0:
                print(f"[INFO] CVE-ID '{cve_id}' not found in database")
                return None
            
            return df
            
        except Exception as e:
            print(f"[ERROR] Failed to query CVE: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def search_cves(self, query, top_k=None):
        """
        Search for CVEs using RAG pipeline - any query is supported.
        If query contains a CVE-ID, queries directly from database first.
        
        Args:
            query: Any search query (e.g., "Apache vulnerabilities", "SQL injection", "CVE-2024-1234")
            top_k: Number of results to return (default: uses self.top_k)
        
        Returns:
            dict with 'answer' (str), 'cves' (DataFrame), 'summary' (str), and 'query' (str)
        """
        if not query or not query.strip():
            return {
                "answer": "No query provided for CVE search.",
                "cves": None,
                "summary": "No query provided for CVE search.",
                "query": query,
                "total_cves": 0
            }
        
        # Check if query contains a CVE-ID - if so, query directly
        import re
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        cve_matches = re.findall(cve_pattern, query, re.IGNORECASE)
        
        if cve_matches:
            # Extract the CVE-ID
            cve_id = cve_matches[0].upper()
            print(f"\n[INFO] Detected CVE-ID in query: {cve_id}")
            print(f"[INFO] Querying CVE directly from database...")
            print("="*80)
            
            # Query directly from database
            cve_df = self.get_cve_by_id(cve_id)
            
            if cve_df is not None and len(cve_df) > 0:
                # Format the CVE information for display
                from RAG_PIPELINE.Rag_generation import generate_answer
                
                # Generate answer about this specific CVE
                answer = generate_answer(
                    user_question=query,
                    cves_df=cve_df,
                    provider=self.provider,
                    model=self.model,
                    conversation_history=self.conversation_history
                )
                
                # Create summary
                summary = f"Found CVE {cve_id} in database."
                
                # Store in conversation history
                self.conversation_history.append({
                    "question": query,
                    "answer": answer,
                    "cves": cve_df
                })
                
                # Update previous_cves
                self.previous_cves = cve_df
                
                return {
                    "answer": answer,
                    "cves": cve_df,
                    "summary": summary,
                    "query": query,
                    "total_cves": 1
                }
            else:
                # CVE not found - fall back to RAG search
                print(f"[INFO] CVE {cve_id} not found, falling back to RAG search...")
        
        # No CVE-ID or CVE not found - use RAG pipeline
        top_k = top_k or self.top_k
        
        print(f"\nSearching CVEs for: '{query}'")
        print("="*80)
        
        try:
            # Use RAG pipeline to search and generate answer
            result = rag_query(
                user_question=query,
                top_k=top_k,
                provider=self.provider,
                model=self.model,
                conversation_history=self.conversation_history,
                previous_cves=self.previous_cves,
                previous_topic=self.previous_topic
            )
            
            # Extract results
            answer = result.get("answer", "No answer generated.")
            retrieved_cves = result.get("retrieved_cves")
            detected_topic = result.get("detected_topic")
            
            # Create summary
            if retrieved_cves is not None and len(retrieved_cves) > 0:
                summary = self._create_summary_from_cves(retrieved_cves, query)
                total_cves = len(retrieved_cves)
            else:
                summary = f"No CVEs found for query: '{query}'"
                total_cves = 0
            
            # Store in conversation history
            self.conversation_history.append({
                "question": query,
                "answer": answer,
                "cves": retrieved_cves
            })
            
            # Update previous_cves and previous_topic for follow-up questions
            self.previous_cves = retrieved_cves
            self.previous_topic = detected_topic
            
            # Limit history to last 5 conversations to avoid token limits
            if len(self.conversation_history) > 5:
                self.conversation_history = self.conversation_history[-5:]
            
            return {
                "answer": answer,
                "cves": retrieved_cves,
                "summary": summary,
                "query": query,
                "total_cves": total_cves
            }
                
        except Exception as e:
            error_msg = f"Failed to search CVEs: {e}"
            print(f"  [ERROR] {error_msg}")
            
            self.conversation_history.append({
                "question": query,
                "answer": error_msg,
                "cves": None
            })
            
            return {
                "answer": error_msg,
                "cves": None,
                "summary": error_msg,
                "query": query,
                "total_cves": 0
            }
    
    def search_cves_for_tech_stack(self, tech_stack, top_k_per_tech=None):
        """
        Search for CVEs for each technology in the tech stack.
        (Kept for backward compatibility with image analysis workflow)
        
        Args:
            tech_stack: List of technologies (e.g., ["Apache", "Docker", "PostgreSQL"])
            top_k_per_tech: Number of CVEs per technology (default: uses self.top_k)
        
        Returns:
            dict with 'results' (dict mapping tech to results) and 'summary' (str)
        """
        if not tech_stack or len(tech_stack) == 0:
            return {
                "results": {},
                "summary": "No technologies provided for CVE search.",
                "total_cves": 0
            }
        
        # FIX: Don't convert None to self.top_k - if None is passed, keep it as None
        # This allows getting all results above similarity threshold
        # Only use default if top_k_per_tech was explicitly set to a number
        # If None is passed, it means "get all results above threshold"
        results = {}
        total_cves = 0
        
        print(f"\nSearching CVEs for {len(tech_stack)} technologies...")
        print("="*80)
        
        for tech in tech_stack:
            print(f"\nSearching CVEs for: {tech}")
            
            try:
                # Use RAG pipeline for each technology
                result = rag_query(
                    user_question=f"{tech} vulnerabilities",
                    top_k=top_k_per_tech,
                    provider=self.provider,
                    model=self.model,
                    conversation_history=None,  # Fresh search for each tech
                    previous_cves=None,
                    similarity_threshold=0.55  # Increased threshold for better relevance
                )
                
                retrieved_cves = result.get("retrieved_cves")
                answer = result.get("answer", "")
                
                if retrieved_cves is not None and len(retrieved_cves) > 0:
                    results[tech] = {
                        "cves": retrieved_cves,
                        "answer": answer
                    }
                    total_cves += len(retrieved_cves)
                    print(f"  Found {len(retrieved_cves)} CVEs for {tech}")
                else:
                    results[tech] = {
                        "cves": None,
                        "answer": answer
                    }
                    print(f"  No CVEs found for {tech}")
                    
            except Exception as e:
                print(f"  [ERROR] Failed to search CVEs for {tech}: {e}")
                results[tech] = {
                    "cves": None,
                    "answer": f"Error: {e}"
                }
        
        # Create summary
        summary = self._create_summary_for_tech_stack(results, total_cves)
        
        # Store in conversation history
        self.conversation_history.append({
            "input": tech_stack,
            "output": results,
            "summary": summary
        })
        
        return {
            "results": results,
            "summary": summary,
            "total_cves": total_cves
        }
    
    def _create_summary_from_cves(self, cves_df, query):
        """
        Create a summary from a single CVE DataFrame.
        
        Args:
            cves_df: DataFrame with CVE results
            query: Original search query
        
        Returns:
            Summary string
        """
        if cves_df is None or len(cves_df) == 0:
            return f"No CVEs found for query: '{query}'"
        
        summary_parts = [f"Found {len(cves_df)} CVEs for query: '{query}'\n"]
        
        # Get severity breakdown
        if 'cvss_severity' in cves_df.columns:
            severity_counts = cves_df['cvss_severity'].value_counts().to_dict()
            severity_str = ", ".join([f"{k}: {v}" for k, v in severity_counts.items()])
            summary_parts.append(f"Severity breakdown: {severity_str}")
        
        # Get top CVE by score
        if 'cvss_score' in cves_df.columns:
            top_cve = cves_df.loc[cves_df['cvss_score'].idxmax()]
            top_cve_id = top_cve.get('cve_id', 'N/A')
            top_score = top_cve.get('cvss_score', 'N/A')
            summary_parts.append(f"Highest CVSS: {top_score} ({top_cve_id})")
        
        # List all CVE IDs
        if 'cve_id' in cves_df.columns:
            cve_ids = cves_df['cve_id'].tolist()
            summary_parts.append(f"CVE IDs: {', '.join(cve_ids)}")
        
        return "\n".join(summary_parts)
    
    def _create_summary_for_tech_stack(self, results, total_cves):
        """
        Create a summary of CVE search results for tech stack.
        
        Args:
            results: Dict mapping technologies to result dicts
            total_cves: Total number of CVEs found
        
        Returns:
            Summary string
        """
        summary_parts = [f"Total CVEs found: {total_cves}\n"]
        
        for tech, tech_result in results.items():
            cves_df = tech_result.get("cves")
            if cves_df is not None and len(cves_df) > 0:
                # Get severity breakdown
                if 'cvss_severity' in cves_df.columns:
                    severity_counts = cves_df['cvss_severity'].value_counts().to_dict()
                    severity_str = ", ".join([f"{k}: {v}" for k, v in severity_counts.items()])
                else:
                    severity_str = "N/A"
                
                # Get top CVE by score
                if 'cvss_score' in cves_df.columns:
                    top_cve = cves_df.loc[cves_df['cvss_score'].idxmax()]
                    top_cve_id = top_cve.get('cve_id', 'N/A')
                    top_score = top_cve.get('cvss_score', 'N/A')
                else:
                    top_cve_id = "N/A"
                    top_score = "N/A"
                
                summary_parts.append(
                    f"{tech}: {len(cves_df)} CVEs found | "
                    f"Severity breakdown: {severity_str} | "
                    f"Highest CVSS: {top_score} ({top_cve_id})"
                )
            else:
                summary_parts.append(f"{tech}: No CVEs found")
        
        return "\n".join(summary_parts)
    
    def get_cves_by_technology(self, technology):
        """
        Get CVEs for a specific technology from previous search results.
        
        Args:
            technology: Technology name
        
        Returns:
            DataFrame with CVEs for that technology, or None
        """
        if not self.conversation_history:
            return None
        
        # Get most recent search results
        last_entry = self.conversation_history[-1]
        
        # Check if it's a tech stack search result
        if isinstance(last_entry.get("output"), dict):
            last_results = last_entry.get("output", {})
            tech_result = last_results.get(technology)
            if tech_result:
                return tech_result.get("cves")
        
        return None
    
    def get_all_cves(self):
        """
        Get all CVEs from the most recent search.
        
        Returns:
            DataFrame with all CVEs, or None
        """
        if self.previous_cves is not None:
            return self.previous_cves
        
        if not self.conversation_history:
            return None
        
        last_entry = self.conversation_history[-1]
        return last_entry.get("cves")
    
    def get_conversation_history(self):
        """
        Get this agent's conversation history.
        
        Returns:
            List of conversation entries
        """
        return self.conversation_history
    
    def clear_history(self):
        """Clear this agent's conversation history."""
        self.conversation_history = []
        self.previous_cves = None

if __name__ == "__main__":
    # Interactive CVE Search Agent with RAG
    agent = CVESearchAgent(top_k=5, provider="openai")
    
    print("="*80)
    print("CVE SEARCH AGENT - RAG Mode (Interactive)")
    print("="*80)
    print("\nEnter your CVE search queries. Type 'quit', 'exit', or 'q' to stop.")
    print("Type 'clear' or 'reset' to clear conversation history.")
    print("\nExamples:")
    print("  - 'Apache vulnerabilities'")
    print("  - 'SQL injection'")
    print("  - 'remote code execution'")
    print("  - 'high severity CVEs'")
    print("  - 'What are the most critical CVEs?'")
    print("  - 'Tell me about Docker security issues'")
    print("-"*80)
    
    while True:
        # Get user query
        query = input("\nEnter your CVE search query: ").strip()
        
        if query.lower() in ['quit', 'exit', 'q']:
            print("\nGoodbye!")
            break
        
        if query.lower() in ['clear', 'reset']:
            agent.clear_history()
            print("\n[INFO] Conversation history cleared.\n")
            continue
        
                # Search for CVEs using RAG
        print("\n" + "="*80)
        result = agent.search_cves(query)
        
        # Display results directly (pure conversation, no prompts)
        print("\n" + "="*80)
        print("ANSWER:")
        print("="*80)
        print(result["answer"])
        print("="*80)
        
        print()  # Just a blank line between questions