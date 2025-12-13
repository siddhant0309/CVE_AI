import sys
import os
import re
# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from patchpath.config.snowflake_config import get_snowflake_session
import pandas as pd

def extract_all_technologies(question):
    """
    Extract ALL technologies/topics from a question.
    PRESERVES multi-word technology names (e.g., "Apache Kafka", "Google Cloud").
    
    Args:
        question: User's question
    
    Returns:
        list: List of extracted technologies (e.g., ["apache kafka", "google cloud"]) or []
    """
    question_lower = question.lower()
    found_techs = []
    
    # STEP 1: Check for KNOWN multi-word tech names FIRST (before single words)
    # This ensures "Apache Kafka" is extracted as "apache kafka", not just "apache"
    known_multi_word_techs = [
        'apache kafka', 'apache airflow', 'apache spark', 'apache flink', 'apache hadoop',
        'apache storm', 'apache beam', 'apache tomcat', 'apache http server', 'apache web server',
        'apache http', 'apache httpd', 'apache server', 'apache web',
        'google cloud', 'google bigquery', 'google cloud platform', 'google kubernetes engine',
        'amazon s3', 'amazon ec2', 'amazon rds', 'amazon ebs', 'amazon vpc', 'amazon lambda',
        'microsoft azure', 'azure functions', 'azure kubernetes service', 'azure sql',
        'delta lake', 'docker compose', 'docker swarm', 'kubernetes cluster',
        'elasticsearch', 'postgresql', 'mongodb', 'redis cluster', 'nginx plus',
        'red hat', 'redhat', 'ubuntu', 'debian', 'centos', 'suse'
    ]
    
    # Check for multi-word techs first (longest first to avoid partial matches)
    for tech in sorted(known_multi_word_techs, key=len, reverse=True):
        if tech in question_lower and tech not in found_techs:
            found_techs.append(tech)
            # Remove from question to avoid re-extracting parts
            question_lower = question_lower.replace(tech, ' ', 1)
    
    # STEP 2: Extract from patterns like "in Python", "for Jenkins", "related to Apache"
    tech_patterns = [
        r'in\s+([a-z]+(?:\s+[a-z]+)?)',  # "in Python", "in Apache HTTP"
        r'for\s+([a-z]+(?:\s+[a-z]+)?)',  # "for Docker"
        r'related\s+to\s+([a-z]+(?:\s+[a-z]+)?)',  # "related to Python"
        r'about\s+([a-z]+(?:\s+[a-z]+)?)',  # "about Jenkins"
    ]
    
    # Common technology keywords (single words)
    tech_keywords = [
        'python', 'java', 'javascript', 'node', 'apache', 'nginx', 'docker', 
        'kubernetes', 'jenkins', 'gitlab', 'github', 'mysql', 'postgresql', 
        'mongodb', 'redis', 'elasticsearch', 'aws', 'azure', 'gcp', 'linux',
        'windows', 'microsoft', 'oracle', 'ibm', 'cisco', 'vmware', 'terraform',
        'ansible', 'puppet', 'chef', 'splunk', 'grafana', 'prometheus', 'kafka',
        'airflow', 'spark', 'flink', 'hadoop', 'storm', 'beam', 'tomcat', 'looker',
        'jupyter', 'dbt', 'databricks', 'snowflake'
    ]
    
    # Extract from patterns (find ALL matches, not just first)
    for pattern in tech_patterns:
        matches = re.findall(pattern, question_lower)  # Find ALL matches
        for match in matches:
            tech = match.strip() if isinstance(match, str) else match[0].strip()
            # Skip if already found as part of multi-word tech
            if any(multi_tech in tech or tech in multi_tech for multi_tech in found_techs):
                continue
            # Check if it's a known technology
            for keyword in tech_keywords:
                if keyword in tech or tech in keyword:
                    if keyword not in found_techs:
                        found_techs.append(keyword)
                    break
            else:
                # If not in known keywords, add it anyway if it looks like a tech name
                if tech and tech not in found_techs and len(tech) > 2:
                    found_techs.append(tech)
    
    # STEP 3: Also check for technologies mentioned directly (e.g., "Jenkins and Python")
    # Look for common separators: "and", "or", ","
    separators = [r'\s+and\s+', r'\s+or\s+', r',\s*', r'\s+&\s+']
    for sep in separators:
        parts = re.split(sep, question_lower)
        for part in parts:
            part = part.strip()
            # Skip if already found as part of multi-word tech
            if any(multi_tech in part or part in multi_tech for multi_tech in found_techs):
                continue
            for keyword in tech_keywords:
                if keyword in part and keyword not in found_techs:
                    found_techs.append(keyword)
    
    # STEP 4: If no technologies found via patterns, check if any keyword appears directly
    # But skip if we already found multi-word techs (to avoid adding "apache" when we have "apache kafka")
    if not found_techs:
        for keyword in tech_keywords:
            if keyword in question_lower and keyword not in found_techs:
                found_techs.append(keyword)
    
    return found_techs

def parse_query_intent(query_text):
    """
    Parse query to detect SQL-style operations and extract parameters.
    
    Args:
        query_text: User's question/query
    
    Returns:
        dict with 'is_sql_style', 'sort_by', 'sort_order', 'filter_by', 'limit', 'semantic_query'
    """
    query_lower = query_text.lower()
    
    result = {
        'is_sql_style': False,
        'sort_by': None,
        'sort_order': 'DESC',  # Default to descending
        'filter_by': {},
        'limit': None,
        'semantic_query': query_text,  # Default semantic query is the full query
        'technologies': []  # Initialize technologies list
    }
    
    # Extract ALL technologies from the query (always, regardless of SQL-style)
    technologies = extract_all_technologies(query_text)
    if technologies:
        result['technologies'] = technologies
        if len(technologies) > 1:
            result['semantic_query'] = f"{' '.join(technologies)} vulnerabilities"
        else:
            result['semantic_query'] = f"{technologies[0]} vulnerabilities"
    
    # Detect SQL-style keywords
    sql_keywords = [
        'top', 'highest', 'lowest', 'maximum', 'minimum', 'max', 'min',
        'sort by', 'order by', 'filter by', 'where', 'group by',
        'count', 'average', 'avg', 'sum', 'most', 'least'
    ]
    
    has_sql_keywords = any(keyword in query_lower for keyword in sql_keywords)
    
    if not has_sql_keywords:
        return result
    
    result['is_sql_style'] = True
    
    # Extract "top N" or "N highest/lowest"
    top_match = re.search(r'top\s+(\d+)', query_lower)
    if top_match:
        result['limit'] = int(top_match.group(1))
    
    # Extract number from "N highest/lowest"
    num_match = re.search(r'(\d+)\s+(highest|lowest|most|least)', query_lower)
    if num_match:
        result['limit'] = int(num_match.group(1))
    
    # Detect sort field
    if 'epss' in query_lower and ('highest' in query_lower or 'top' in query_lower or 'maximum' in query_lower):
        result['sort_by'] = 'EPSS_SCORE'
        result['sort_order'] = 'DESC'
        # Filter out NULL or 0 EPSS scores
        result['filter_by']['EPSS_SCORE'] = {'operator': '>', 'value': 0}
    elif 'epss' in query_lower and ('lowest' in query_lower or 'minimum' in query_lower):
        result['sort_by'] = 'EPSS_SCORE'
        result['sort_order'] = 'ASC'
        result['filter_by']['EPSS_SCORE'] = {'operator': 'IS NOT NULL', 'value': None}
    elif 'cvss' in query_lower and ('highest' in query_lower or 'top' in query_lower or 'maximum' in query_lower or 'most severe' in query_lower):
        result['sort_by'] = 'CVSS_SCORE'
        result['sort_order'] = 'DESC'
    elif 'cvss' in query_lower and ('lowest' in query_lower or 'minimum' in query_lower):
        result['sort_by'] = 'CVSS_SCORE'
        result['sort_order'] = 'ASC'
    
    # Technologies are already extracted at the beginning of the function
    # If no technologies were found, try fallback pattern matching
    if not result['technologies']:
        tech_patterns = [
            r'in\s+([a-z]+(?:\s+[a-z]+)?)',  # "in Python", "in Apache HTTP"
            r'for\s+([a-z]+(?:\s+[a-z]+)?)',  # "for Docker"
            r'related\s+to\s+([a-z]+(?:\s+[a-z]+)?)',  # "related to Python"
        ]
        
        for pattern in tech_patterns:
            match = re.search(pattern, query_lower)
            if match:
                tech = match.group(1).strip()
                result['semantic_query'] = f"{tech} vulnerabilities"
                result['technologies'] = [tech]
                break
    
    return result

def search_similar_cves_multi_tech(technologies, top_k_per_tech=10, query_text="", similarity_threshold=0.55):
    """
    Search for CVEs across multiple technologies and combine results.
    
    Args:
        technologies: List of technology names to search for
        top_k_per_tech: Number of CVEs to retrieve per technology. Use None for all results above threshold.
        query_text: Original query text (for context)
        similarity_threshold: Minimum similarity score (0.0-1.0). Default: 0.55
    
    Returns:
        pandas DataFrame with combined CVEs from all technologies
    """
    import pandas as pd
    all_cves = []
    
    print(f"Searching CVEs for {len(technologies)} technologies: {', '.join(technologies)}")
    
    for tech in technologies:
        print(f"  Searching: {tech}...")
        tech_query = f"{tech} vulnerabilities"
        cves = search_similar_cves(tech_query, top_k=top_k_per_tech, similarity_threshold=similarity_threshold)
        
        if cves is not None and len(cves) > 0:
            # Add technology tag to identify which tech this CVE belongs to
            cves_copy = cves.copy()
            cves_copy['detected_technology'] = tech
            all_cves.append(cves_copy)
            print(f"    Found {len(cves)} CVEs for {tech}")
        else:
            print(f"    No CVEs found for {tech}")
    
    if all_cves:
        # Combine all DataFrames
        combined_df = pd.concat(all_cves, ignore_index=True)
        # Remove duplicates based on CVE_ID (keep first occurrence)
        combined_df = combined_df.drop_duplicates(subset=['cve_id'], keep='first')
        print(f"\n[OK] Combined results: {len(combined_df)} unique CVEs from {len(technologies)} technologies\n")
        return combined_df
    else:
        print(f"\n[INFO] No CVEs found for any of the technologies\n")
        return None

def search_similar_cves_hybrid(query_text, top_k=10, similarity_threshold=0.55):
    """
    Hybrid search: Combines semantic vector search with SQL-style filtering and sorting.
    Handles multiple technologies in a single query.
    
    Args:
        query_text: User's question/query
        top_k: Number of top results to return (default: 10). Use None for all results above threshold.
        similarity_threshold: Minimum similarity score (0.0-1.0). Default: 0.55
    
    Returns:
        pandas DataFrame with matching CVEs
    """
    # Parse query intent
    intent = parse_query_intent(query_text)
    
    # Check if multiple technologies are detected
    technologies = intent.get('technologies', [])
    
    # If multiple technologies detected, search each separately and combine
    if technologies and len(technologies) > 1:
        print(f"[INFO] Detected multiple technologies: {', '.join(technologies)}")
        # Calculate top_k per technology (distribute evenly) if top_k is specified
        if top_k is not None:
            top_k_per_tech = max(5, top_k // len(technologies))  # At least 5 per tech
        else:
            top_k_per_tech = None  # Get all results for each tech
        return search_similar_cves_multi_tech(technologies, top_k_per_tech=top_k_per_tech, query_text=query_text, similarity_threshold=similarity_threshold)
    
    # If not SQL-style, use regular semantic search
    if not intent['is_sql_style']:
        return search_similar_cves(query_text, top_k=top_k, similarity_threshold=similarity_threshold)
    
    # Use semantic query for initial retrieval (broader search)
    semantic_query = intent['semantic_query']
    # Retrieve more results initially for filtering/sorting
    if top_k is not None:
        initial_top_k = intent['limit'] if intent['limit'] else top_k * 3  # Get more for filtering
    else:
        initial_top_k = None  # Get all results
    
    try:
        print(f"Hybrid search: '{query_text}'")
        print(f"  - Semantic query: '{semantic_query}'")
        print(f"  - Sort by: {intent['sort_by']} {intent['sort_order']}")
        if intent['limit']:
            print(f"  - Limit: {intent['limit']}")
        print(f"  - Similarity threshold: {similarity_threshold}")
        
        session = get_snowflake_session()
        
        # Build the hybrid query
        search_query = f"""
        WITH query_embedding AS (
            SELECT SNOWFLAKE.CORTEX.EMBED_TEXT_1024(
                'snowflake-arctic-embed-l-v2.0',
                '{semantic_query.replace("'", "''")}'
            )::VECTOR(FLOAT, 1024) AS query_vec
        ),
        ranked_results AS (
            SELECT 
                v.*,
                VECTOR_COSINE_SIMILARITY(
                    v.EMBEDDING_VECTOR,
                    q.query_vec
                ) AS similarity_score,
                ROW_NUMBER() OVER (
                    PARTITION BY v.CVE_ID 
                    ORDER BY VECTOR_COSINE_SIMILARITY(v.EMBEDDING_VECTOR, q.query_vec) DESC
                ) AS rn
            FROM TESTCVE.CVE.VULN_GOLD_FINAL v
            CROSS JOIN query_embedding q
            WHERE v.EMBEDDING_VECTOR IS NOT NULL
        ),
        filtered_results AS (
            SELECT *
            FROM ranked_results
            WHERE rn = 1
                AND similarity_score >= {similarity_threshold}
        """
        
        # Add filters
        where_conditions = []
        if intent['filter_by']:
            for field, condition in intent['filter_by'].items():
                if condition['operator'] == '>':
                    where_conditions.append(f"{field} > {condition['value']}")
                elif condition['operator'] == 'IS NOT NULL':
                    where_conditions.append(f"{field} IS NOT NULL")
        
        if where_conditions:
            search_query += " AND " + " AND ".join(where_conditions)
        
        search_query += "\n        )\n        SELECT *\n        FROM filtered_results"
        
        # Add sorting
        if intent['sort_by']:
            search_query += f"\n        ORDER BY {intent['sort_by']} {intent['sort_order']}"
        else:
            search_query += "\n        ORDER BY similarity_score DESC"
        
        # Add limit only if specified
        final_limit = intent['limit'] if intent['limit'] else top_k
        if final_limit is not None:
            search_query += f"\n        LIMIT {final_limit}"
        search_query += "\n        "
        
        print("Executing hybrid search query...")
        results = session.sql(search_query)
        df = results.to_pandas()
        
        # Normalize column names to lowercase
        df.columns = df.columns.str.lower()
        
        print(f"[OK] Found {len(df)} results\n")
        session.close()
        
        return df
        
    except Exception as e:
        print(f"[ERROR] Hybrid search failed: {e}")
        import traceback
        traceback.print_exc()
        # Fallback to regular semantic search
        print("[INFO] Falling back to regular semantic search...")
        return search_similar_cves(query_text, top_k=top_k, similarity_threshold=similarity_threshold)

def search_similar_cves(query_text, top_k=10, similarity_threshold=0.55):
    """
    Search for similar CVEs using keyword matching first, then vector similarity ranking.
    PRESERVES multi-word technology names in keyword extraction.
    """
    try:
        print(f"Searching for: '{query_text}'...")
        session = get_snowflake_session()
        
        # Extract keywords from query (remove common words)
        import re
        stop_words = {
            'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by', 
            'vulnerabilities', 'vulnerability', 'cve', 'cves', 'what', 'are', 'is', 'this', 'that', 
            'these', 'those', 'my', 'your', 'our', 'their', 'stack', 'tech', 'technology', 'technologies',
            'give', 'me', 'show', 'tell', 'find', 'search', 'list', 'all', 'get', 'can', 'you',
            'above', 'below', 'mentioned', 'detected', 'returned', 'previous'
        }
        
        # IMPROVED: Dynamically extract multi-word tech names from query
        query_lower = query_text.lower()
        keywords = []
        remaining_query = query_lower
        
        # Common technology prefixes that typically have multi-word names
        tech_prefixes = [
            'apache', 'google', 'amazon', 'microsoft', 'azure', 'aws', 'gcp',
            'oracle', 'ibm', 'cisco', 'vmware', 'red hat', 'redhat', 'ubuntu',
            'debian', 'centos', 'suse', 'docker', 'kubernetes', 'jenkins',
            'gitlab', 'github', 'terraform', 'ansible', 'puppet', 'chef',
            'splunk', 'grafana', 'prometheus', 'elastic', 'mongodb', 'postgres',
            'mysql', 'redis', 'nginx', 'delta', 'databricks', 'snowflake'
        ]
        
        # Strategy 1: Extract multi-word tech names by detecting prefix + word patterns
        # Pattern: "prefix word" (e.g., "apache kafka", "google cloud")
        for prefix in tech_prefixes:
            # Look for pattern: prefix followed by a word (not a stop word)
            pattern = rf'\b{re.escape(prefix)}\s+(\w+)\b'
            matches = re.finditer(pattern, remaining_query)
            for match in matches:
                full_phrase = match.group(0)  # e.g., "apache kafka"
                second_word = match.group(1)  # e.g., "kafka"
                # Only add if second word is not a stop word and is meaningful
                if second_word not in stop_words and len(second_word) > 2:
                    if full_phrase not in keywords:
                        keywords.append(full_phrase)
                        # Remove from remaining query to avoid duplicate extraction
                        remaining_query = remaining_query.replace(full_phrase, ' ', 1)
        
        # Strategy 2: Also check for known multi-word tech names (fallback)
        known_multi_word_techs = [
            'apache kafka', 'apache airflow', 'apache spark', 'apache flink', 'apache hadoop',
            'apache storm', 'apache beam', 'apache tomcat', 'apache http server', 'apache web server',
            'google cloud', 'google bigquery', 'google cloud platform', 'google kubernetes engine',
            'amazon s3', 'amazon ec2', 'amazon rds', 'amazon ebs', 'amazon vpc', 'amazon lambda',
            'microsoft azure', 'azure functions', 'azure kubernetes service', 'azure sql',
            'delta lake', 'docker compose', 'docker swarm', 'kubernetes cluster',
            'elasticsearch', 'postgresql', 'mongodb', 'redis cluster', 'nginx plus',
            'apache http', 'apache httpd', 'apache server', 'apache web'
        ]
        
        for tech in known_multi_word_techs:
            if tech in remaining_query and tech not in keywords:
                keywords.append(tech)
                remaining_query = remaining_query.replace(tech, ' ', 1)
        
        # Strategy 3: Extract single words from remaining query
        words = re.findall(r'\b\w+\b', remaining_query)
        single_keywords = [w for w in words if w not in stop_words and len(w) > 2]
        keywords.extend(single_keywords)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_keywords = []
        for kw in keywords:
            kw_lower = kw.lower()
            if kw_lower not in seen:
                seen.add(kw_lower)
                unique_keywords.append(kw)
        keywords = unique_keywords
        
        # If no meaningful keywords extracted, fall back to using the full query for semantic search only
        if not keywords:
            print("  No meaningful keywords found - using semantic search only (no keyword filtering)...")
            # Fall back to original semantic search without keyword filtering
            search_query = f"""
            WITH query_embedding AS (
                SELECT SNOWFLAKE.CORTEX.EMBED_TEXT_1024(
                    'snowflake-arctic-embed-l-v2.0',
                    '{query_text.replace("'", "''")}'
                )::VECTOR(FLOAT, 1024) AS query_vec
            ),
            ranked_results AS (
                SELECT 
                    v.*,
                    VECTOR_COSINE_SIMILARITY(
                        v.EMBEDDING_VECTOR,
                        q.query_vec
                    ) AS similarity_score,
                    ROW_NUMBER() OVER (
                        PARTITION BY v.CVE_ID 
                        ORDER BY VECTOR_COSINE_SIMILARITY(v.EMBEDDING_VECTOR, q.query_vec) DESC
                    ) AS rn
                FROM TESTCVE.CVE.VULN_GOLD_FINAL v
                CROSS JOIN query_embedding q
                WHERE v.EMBEDDING_VECTOR IS NOT NULL
            )
            SELECT 
                *
            FROM ranked_results
            WHERE rn = 1
                AND similarity_score >= {similarity_threshold}
            ORDER BY similarity_score DESC
            LIMIT 15
            """
        else:
            print(f"  Extracted keywords: {', '.join(keywords)}")
            print("  Step 1: Keyword matching across ALL CVEs in database...")
            
            # Build keyword matching conditions (LIKE for each keyword)
            keyword_conditions = []
            for keyword in keywords:
                # Search in title, description, and combined_text columns
                keyword_escaped = keyword.replace("'", "''")
                # For multi-word keywords, match the entire phrase
                # For single words, match as before
                keyword_conditions.append(f"""
                    (UPPER(COALESCE(v.TITLE, '')) LIKE UPPER('%{keyword_escaped}%')
                    OR UPPER(COALESCE(v.DESCRIPTION, '')) LIKE UPPER('%{keyword_escaped}%')
                    OR UPPER(COALESCE(v.COMBINED_TEXT, '')) LIKE UPPER('%{keyword_escaped}%'))
                """)
            
            keyword_where = " OR ".join(keyword_conditions)
            
            # Step 2: Calculate cosine similarity for keyword matches and return top 15
            search_query = f"""
            WITH query_embedding AS (
                SELECT SNOWFLAKE.CORTEX.EMBED_TEXT_1024(
                    'snowflake-arctic-embed-l-v2.0',
                    '{query_text.replace("'", "''")}'
                )::VECTOR(FLOAT, 1024) AS query_vec
            ),
            keyword_matches AS (
                SELECT 
                    v.*
                FROM TESTCVE.CVE.VULN_GOLD_FINAL v
                WHERE v.EMBEDDING_VECTOR IS NOT NULL
                    AND ({keyword_where})
            ),
            ranked_results AS (
                SELECT 
                    km.*,
                    VECTOR_COSINE_SIMILARITY(
                        km.EMBEDDING_VECTOR,
                        q.query_vec
                    ) AS similarity_score,
                    ROW_NUMBER() OVER (
                        PARTITION BY km.CVE_ID 
                        ORDER BY VECTOR_COSINE_SIMILARITY(km.EMBEDDING_VECTOR, q.query_vec) DESC
                    ) AS rn
                FROM keyword_matches km
                CROSS JOIN query_embedding q
            )
            SELECT 
                *
            FROM ranked_results
            WHERE rn = 1
                AND similarity_score >= {similarity_threshold}
            ORDER BY similarity_score DESC
            LIMIT 15
            """
        
        print("  Step 2: Calculating cosine similarity for keyword matches...")
        print("  Step 3: Returning top 15 by similarity score...")
        
        results = session.sql(search_query)
        df = results.to_pandas()
        
        # Normalize column names to lowercase (Snowflake returns uppercase)
        df.columns = df.columns.str.lower()
        
        print(f"[OK] Found {len(df)} results (top 15 by similarity)\n")
        session.close()
        
        return df
        
    except Exception as e:
        print(f"[ERROR] Search failed: {e}")
        import traceback
        traceback.print_exc()
        return None

def display_results(df):
    """
    Display search results in a readable format.
    Shows all available columns from the DataFrame.
    """
    if df is None or len(df) == 0:
        print("No results found.")
        return
    
    print("="*80)
    print("SEARCH RESULTS")
    print("="*80)
    
    # Columns to exclude from display (internal/technical columns)
    exclude_cols = {'embedding_vector', 'rn', 'similarity_score'}
    
    for idx, row in df.iterrows():
        print(f"\n[{idx + 1}] CVE: {row['cve_id']}")
        
        # Show similarity score first if available
        if 'similarity_score' in df.columns:
            print(f"    Similarity Score: {row['similarity_score']:.4f}")
        
        # Display all other columns dynamically
        for col in df.columns:
            col_lower = col.lower()
            if col_lower not in exclude_cols and col_lower != 'cve_id':
                value = row[col]
                if pd.notna(value):
                    # Format column name nicely
                    col_name = col.replace('_', ' ').title()
                    
                    # Handle long text fields
                    if isinstance(value, str) and len(value) > 200:
                        print(f"    {col_name}: {value[:200]}...")
                    else:
                        print(f"    {col_name}: {value}")
        
        print("-" * 80)

if __name__ == "__main__":
    # Test the vector search
    print("="*80)
    print("VECTOR SEARCH TEST")
    print("="*80)
    print()
    
    # Example query to test - change this to test different queries
    query = "Apache vulnerabilities"
    print(f"Test query: '{query}'\n")
    
    results = search_similar_cves(query, top_k=5)
    
    if results is not None:
        display_results(results)
        
        print("\n" + "="*80)
        print("Summary Table:")
        print("="*80)
        # Show all columns except technical/internal ones
        exclude_cols = ['embedding_vector', 'rn']
        display_cols = [col for col in results.columns if col.lower() not in exclude_cols]
        # Limit to first 10 columns for readability, or show all if fewer
        if len(display_cols) > 10:
            # Show key columns first, then others
            key_cols = ['cve_id', 'title', 'similarity_score', 'cvss_score', 'cvss_severity', 'epss_score']
            other_cols = [col for col in display_cols if col.lower() not in [c.lower() for c in key_cols]]
            display_cols = [col for col in key_cols if col.lower() in [c.lower() for c in results.columns]] + other_cols[:4]
        print(results[display_cols].to_string())