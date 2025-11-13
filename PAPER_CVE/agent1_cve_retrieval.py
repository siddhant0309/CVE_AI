"""
Agent 1: CVE Retrieval Specialist
Input: User's tech stack
Output: Relevant CVEs from vector database
"""

import json
import os
from pathlib import Path
from typing import List, Dict, Optional
import chromadb
from sentence_transformers import SentenceTransformer
from openai import OpenAI
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Initialize components
print("Initializing Agent 1: CVE Retrieval Specialist...\n")

# Load embedding model for vector search
EMBEDDING_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
embedding_model = SentenceTransformer(EMBEDDING_MODEL)
print(f"[OK] Loaded embedding model: {EMBEDDING_MODEL}")

# Initialize ChromaDB
chroma_client = chromadb.PersistentClient(path="./chroma_db")
collection = chroma_client.get_collection(name="cve_embeddings")
print("[OK] Connected to vector database\n")

# Initialize LLM (OpenAI - can be changed to other models)
try:
    api_key = os.getenv("OPENAI_API_KEY")
    if api_key and api_key.strip():
        llm_client = OpenAI(api_key=api_key)
        LLM_MODEL = "gpt-3.5-turbo"
        print(f"[OK] Using LLM: {LLM_MODEL}")
    else:
        llm_client = None
        print("[WARNING] OPENAI_API_KEY not found. Agent will work without LLM enhancement.")
        print("Set OPENAI_API_KEY in .env file to enable LLM features.")
except Exception as e:
    llm_client = None
    print(f"[WARNING] LLM initialization failed: {e}")
    print("Agent will work in basic mode (vector search only)\n")


class CVERetrievalAgent:
    """Agent 1: CVE Retrieval Specialist"""
    
    def __init__(self, collection, embedding_model, llm_client=None):
        self.collection = collection
        self.embedding_model = embedding_model
        self.llm_client = llm_client
    
    def extract_tech_stack(self, user_input: str) -> str:
        """Extract and format technology stack from user input using LLM"""
        if not self.llm_client:
            # Basic mode: return user input as-is
            return user_input
        
        try:
            prompt = f"""Extract the technology stack from the following user input.
Return only the technologies, frameworks, and tools mentioned, separated by commas.
Example: "Python 3.9, PostgreSQL 14, React 18" → "Python, PostgreSQL, React"

User input: {user_input}

Technologies:"""
            
            response = self.llm_client.chat.completions.create(
                model=LLM_MODEL,
                messages=[
                    {"role": "system", "content": "You are a technology stack extractor. Return only technology names."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=100,
                temperature=0.1
            )
            
            tech_stack = response.choices[0].message.content.strip()
            return tech_stack
        except Exception as e:
            print(f"[WARNING] LLM extraction failed: {e}. Using basic mode.")
            return user_input
    
    def extract_tech_keywords(self, tech_stack: str) -> List[str]:
        """Extract technology keywords from user input"""
        # Common technology names to match
        tech_keywords = []
        tech_stack_lower = tech_stack.lower()
        
        # Common technologies in our database
        all_techs = [
            'python', 'node.js', 'nodejs', 'react', 'postgresql', 'mongodb', 'redis',
            'docker', 'kubernetes', 'nginx', 'apache', 'tensorflow', 'pytorch', 'java',
            'spring boot', 'php', 'wordpress', 'ruby', 'rails', 'go', 'rust', 'c++',
            'javascript', 'typescript', 'angular', 'vue.js', 'express', 'django', 'flask',
            'elasticsearch', 'kafka', 'zookeeper', 'cassandra', 'grafana', 'mysql'
        ]
        
        for tech in all_techs:
            if tech.lower() in tech_stack_lower:
                # Normalize names
                if tech.lower() in ['node.js', 'nodejs']:
                    tech_keywords.append('Node.js')
                else:
                    tech_keywords.append(tech.title() if tech.islower() else tech)
        
        return tech_keywords
    
    def search_cves(self, tech_stack: str, top_k: int = 10, strict_filter: bool = True) -> List[Dict]:
        """Search for relevant CVEs using vector embeddings with technology filtering"""
        print(f"\nSearching CVEs for tech stack: {tech_stack}")
        
        # Extract technology keywords
        tech_keywords = self.extract_tech_keywords(tech_stack)
        print(f"Extracted technologies: {tech_keywords}")
        
        # Create embedding for tech stack query
        query_embedding = self.embedding_model.encode([tech_stack])
        
        # Search with more results to filter
        search_k = top_k * 3 if strict_filter else top_k  # Get more results to filter
        
        # Search vector database
        results = self.collection.query(
            query_embeddings=query_embedding.tolist(),
            n_results=search_k
        )
        
        # Format results and filter
        cves = []
        for i, (cve_id, distance, metadata, document) in enumerate(zip(
            results['ids'][0],
            results['distances'][0],
            results['metadatas'][0],
            results['documents'][0]
        )):
            cve_techs = [t.strip() for t in metadata.get('technologies', '').split(',') if t.strip()]
            cve_techs_lower = [t.lower() for t in cve_techs]
            
            # If strict filtering and we have tech keywords, check if CVE matches
            if strict_filter and tech_keywords:
                # Normalize tech keywords for comparison
                tech_keywords_normalized = []
                for keyword in tech_keywords:
                    # Normalize variations
                    if keyword.lower() in ['node.js', 'nodejs', 'node']:
                        tech_keywords_normalized.extend(['node.js', 'nodejs', 'node'])
                    else:
                        tech_keywords_normalized.append(keyword.lower())
                
                # Check if any of the user's technologies are in this CVE
                matches = any(
                    keyword in cve_techs_lower or 
                    any(cve_tech in keyword or keyword in cve_tech for cve_tech in cve_techs_lower)
                    for keyword in tech_keywords_normalized
                )
                
                if not matches:
                    continue  # Skip this CVE if it doesn't match user's tech stack
            
            cve = {
                'cve_id': cve_id,
                'description': metadata.get('description', ''),
                'cvss_v3_score': metadata.get('cvss_v3_score'),
                'severity': metadata.get('severity', ''),
                'technologies': cve_techs if cve_techs else metadata.get('technologies', '').split(', '),
                'affected_products': metadata.get('affected_products', '').split(', ') if metadata.get('affected_products') else [],
                'similarity_score': round(1 - distance, 4),  # Convert distance to similarity
                'rank': len(cves) + 1
            }
            cves.append(cve)
            
            # Stop when we have enough filtered results
            if len(cves) >= top_k:
                break
        
        print(f"[OK] Found {len(cves)} relevant CVEs (filtered to match tech stack)\n")
        return cves
    
    def format_output(self, cves: List[Dict]) -> str:
        """Format CVE results for display"""
        if not cves:
            return "No relevant CVEs found for the given tech stack."
        
        output = f"\n=== Found {len(cves)} Relevant CVEs ===\n\n"
        
        for cve in cves:
            output += f"Rank {cve['rank']}: {cve['cve_id']}\n"
            output += f"  Severity: {cve['severity']}\n"
            output += f"  CVSS v3: {cve['cvss_v3_score']}\n"
            output += f"  Technologies: {', '.join(cve['technologies'])}\n"
            output += f"  Similarity: {cve['similarity_score']}\n"
            output += f"  Description: {cve['description'][:150]}...\n"
            output += "\n"
        
        return output
    
    def process(self, user_input: str, top_k: int = 10, strict_filter: bool = True) -> Dict:
        """Main processing function for Agent 1"""
        print(f"\n=== Agent 1: CVE Retrieval Specialist ===\n")
        print(f"Input: {user_input}")
        
        # Step 1: Extract tech stack (with LLM if available)
        tech_stack = self.extract_tech_stack(user_input)
        print(f"Extracted tech stack: {tech_stack}")
        
        # Step 2: Search for relevant CVEs with filtering
        cves = self.search_cves(tech_stack, top_k=top_k, strict_filter=strict_filter)
        
        # Step 3: Format output
        formatted_output = self.format_output(cves)
        
        # Return structured output
        return {
            'tech_stack': tech_stack,
            'cves': cves,
            'count': len(cves),
            'formatted_output': formatted_output
        }


def main():
    """Test Agent 1"""
    # Initialize agent
    agent = CVERetrievalAgent(collection, embedding_model, llm_client)
    
    # Example test queries
    test_queries = [
        "I'm using Python 3.9 and PostgreSQL 14 in my application",
        "My tech stack includes React, Node.js, and MongoDB",
        "Python vulnerability"
    ]
    
    print("=== Testing Agent 1 ===\n")
    
    # Test with first query
    test_query = test_queries[0]
    result = agent.process(test_query, top_k=5)
    
    print(result['formatted_output'])
    
    # Return result for next agent
    print("\n=== Agent 1 Output (for Agent 2) ===")
    print(f"CVE List: {[cve['cve_id'] for cve in result['cves']]}")
    print(f"Total CVEs found: {result['count']}")


if __name__ == "__main__":
    main()

