import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import os
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage
import pandas as pd
import re

load_dotenv()

from patchpath.config.snowflake_config import get_snowflake_session

class RiskMitigationAgent:
    """
    Agent that generates mitigation roadmaps for specific CVE-IDs.
    Takes a CVE-ID, retrieves CVE details from database, and generates a step-by-step mitigation plan.
    """
    
    def __init__(self, provider="openai", model="gpt-4o-mini", temperature=0.3):
        """
        Initialize the Risk Mitigation Agent.
        
        Args:
            provider: LLM provider - "openai" or "anthropic" (default: "openai")
            model: Model name (default: "gpt-4o-mini")
            temperature: Model temperature (default: 0.3 for more factual)
        """
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY not found in environment variables")
        
        self.provider = provider
        self.model = model
        self.temperature = temperature
        
        # Initialize LLM
        if provider == "openai":
            self.llm = ChatOpenAI(
                model=model,
                temperature=temperature,
                api_key=api_key
            )
        else:
            raise ValueError(f"Provider {provider} not supported. Use 'openai'.")
        
        self.conversation_history = []  # Individual agent memory
        self.previous_cve = None  # Store previous CVE for follow-up questions
    
    def _extract_cve_ids(self, text):
        """
        Extract ALL CVE-IDs from text using regex, even if there are extra words.
        
        Args:
            text: Text that may contain CVE-IDs (e.g., "CVE-2024-50603, CVE-2024-57937 give me mitigation plan")
        
        Returns:
            List of extracted CVE-IDs (e.g., ["CVE-2024-50603", "CVE-2024-57937"]) or empty list if none found
        """
        if not text:
            return []
        
        # Pattern to match CVE-ID: CVE-YYYY-NNNNN (4 digits, dash, 4-7 digits)
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        matches = re.findall(cve_pattern, text.upper())
        
        # Remove duplicates and return list
        return list(set(matches))
    
    def _extract_cve_id(self, text):
        """
        Extract first CVE-ID from text (for backward compatibility).
        
        Args:
            text: Text that may contain a CVE-ID
        
        Returns:
            First extracted CVE-ID or None if not found
        """
        cve_ids = self._extract_cve_ids(text)
        return cve_ids[0] if cve_ids else None
    
    def get_cve_by_id(self, cve_id):
        """
        Query Snowflake directly for a specific CVE-ID.
        
        Args:
            cve_id: CVE identifier (e.g., "CVE-2024-1234") or text containing CVE-ID
        
        Returns:
            pandas DataFrame with CVE details, or None if not found
        """
        try:
            # Extract CVE-ID from text if needed
            if not cve_id.upper().startswith('CVE-') or not re.match(r'^CVE-\d{4}-\d{4,7}$', cve_id.upper()):
                extracted = self._extract_cve_id(cve_id)
                if extracted:
                    cve_id = extracted
                else:
                    print(f"[WARNING] Could not extract valid CVE-ID from: {cve_id}")
                    print("[INFO] Expected format: CVE-YYYY-NNNNN (e.g., CVE-2024-1234)")
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
    
    def _format_cves_for_llm(self, cve_dfs):
        """
        Format multiple CVE DataFrames into text for LLM context.
        
        Args:
            cve_dfs: List of DataFrames with CVE details, or single DataFrame
        
        Returns:
            Formatted string with CVE information for all CVEs
        """
        # Handle single DataFrame for backward compatibility
        if isinstance(cve_dfs, pd.DataFrame):
            cve_dfs = [cve_dfs]
        
        if not cve_dfs or all(df is None or len(df) == 0 for df in cve_dfs):
            return "No CVE information available."
        
        cve_info_parts = []
        
        for idx, cve_df in enumerate(cve_dfs):
            if cve_df is None or len(cve_df) == 0:
                continue
            
            row = cve_df.iloc[0]
            cve_info = f"""CVE {idx + 1}:
CVE ID: {row.get('cve_id', 'N/A')}
Title: {row.get('title', 'N/A')}
"""
            
            # Add CVSS information
            if pd.notna(row.get('cvss_score')):
                cvss_score = row.get('cvss_score')
                cvss_severity = row.get('cvss_severity', 'N/A')
                cve_info += f"CVSS Score: {cvss_score} ({cvss_severity})\n"
            
            # Add EPSS information
            if pd.notna(row.get('epss_score')):
                epss_score = row.get('epss_score')
                epss_percentage = round(epss_score * 100, 2)
                cve_info += f"EPSS Score: {epss_score} ({epss_percentage}% probability of exploitation)\n"
            
            # Add description
            if pd.notna(row.get('description')):
                desc = str(row.get('description'))
                if len(desc) > 1000:
                    cve_info += f"Description: {desc[:1000]}...\n"
                else:
                    cve_info += f"Description: {desc}\n"
            
            # Add other relevant fields
            relevant_fields = [
                'published_date', 'modified_date', 'vendor', 'product', 
                'affected_version', 'fixed_version', 'cwe_id', 'cwe_name'
            ]
            
            for field in relevant_fields:
                if pd.notna(row.get(field)):
                    value = row.get(field)
                    field_name = field.replace('_', ' ').title()
                    cve_info += f"{field_name}: {value}\n"
            
            cve_info_parts.append(cve_info)
        
        return "\n---\n".join(cve_info_parts)
    
    def _format_cve_for_llm(self, cve_df):
        """
        Format single CVE DataFrame into text for LLM context (for backward compatibility).
        
        Args:
            cve_df: DataFrame with CVE details
        
        Returns:
            Formatted string with CVE information
        """
        return self._format_cves_for_llm(cve_df)
    
    def _generate_roadmap_with_llm(self, cve_info, cve_ids):
        """
        Use LLM to generate mitigation roadmap for one or more CVEs.
        
        Args:
            cve_info: Formatted CVE information string (can be for multiple CVEs)
            cve_ids: Single CVE-ID string or list of CVE-IDs
        
        Returns:
            Generated roadmap string
        """
        try:
            # Handle both single CVE-ID and list
            if isinstance(cve_ids, list):
                cve_id_str = ", ".join(cve_ids)
            else:
                cve_id_str = cve_ids
            
            system_prompt = """You are a cybersecurity expert specializing in vulnerability mitigation. 
Your task is to create a concise, actionable mitigation roadmap for CVEs.

Generate ONLY 5-7 key mitigation steps per CVE that include:
1. Immediate critical actions (patches, updates)
2. Short-term fixes (workarounds, configurations)
3. Long-term prevention (best practices)

For each step, provide:
- A clear, actionable description
- Priority level (Critical/High/Medium/Low)

Keep steps concise and focused on actionable items. Do NOT include formatting labels like "Action:", "Timeline:", "Technical Recommendation:" - just write the step directly.

If multiple CVEs are provided, create separate sections for each CVE with 5-7 steps each."""
            
            if isinstance(cve_ids, list) and len(cve_ids) > 1:
                user_prompt = f"""Based on the following CVE information, generate a concise mitigation roadmap with 5-7 key steps for EACH CVE.

{cve_info}

CVE IDs: {cve_id_str}

For each CVE, provide exactly 5-7 numbered steps (1., 2., 3., etc.) with:
- Clear, actionable mitigation actions
- Priority level (Critical/High/Medium/Low) for each step

Format: Just numbered steps with priority in brackets, like:
1. [High] Apply the security patch from vendor
2. [Medium] Update affected software to latest version
3. [Critical] Isolate affected systems from network

Do NOT use formatting labels like "Action:", "Timeline:", "Technical Recommendation:" - just write the steps directly."""
            else:
                user_prompt = f"""Based on the following CVE information, generate a concise mitigation roadmap with 5-7 key steps.

{cve_info}

CVE ID: {cve_id_str}

Provide exactly 5-7 numbered steps (1., 2., 3., etc.) with:
- Clear, actionable mitigation actions
- Priority level (Critical/High/Medium/Low) for each step

Format: Just numbered steps with priority in brackets, like:
1. [High] Apply the security patch from vendor
2. [Medium] Update affected software to latest version
3. [Critical] Isolate affected systems from network

Do NOT use formatting labels like "Action:", "Timeline:", "Technical Recommendation:" - just write the steps directly."""
            
            messages = [
                SystemMessage(content=system_prompt),
                HumanMessage(content=user_prompt)
            ]
            
            # Add conversation history if available
            if self.conversation_history:
                for item in self.conversation_history[-3:]:  # Last 3 conversations
                    messages.append(HumanMessage(content=f"Previous context: {item.get('question', '')}"))
                    messages.append(HumanMessage(content=f"Previous answer: {item.get('answer', '')}"))
            
            response = self.llm.invoke(messages)
            roadmap = response.content
            
            return roadmap
            
        except Exception as e:
            print(f"[WARNING] LLM roadmap generation failed: {e}")
            return f"Error generating roadmap: {e}"
    
    def _parse_roadmap_steps(self, roadmap_text, cve_ids=None):
        """
        Parse LLM response into structured steps with better extraction.
        Improved to handle multiple CVEs and steps that apply to "Both" or all CVEs.
        More flexible to catch steps in various formats.
        
        Args:
            roadmap_text: LLM-generated roadmap text
            cve_ids: List of CVE-IDs to help organize steps by CVE
        
        Returns:
            Dict with CVE-ID as key and list of steps as value, or list of steps if single CVE
        """
        if not roadmap_text:
            return None
        
        # Initialize result structure
        if cve_ids and len(cve_ids) > 1:
            result = {cve_id: [] for cve_id in cve_ids}
            result['BOTH'] = []  # For steps that apply to all CVEs
        else:
            result = []
        
        # Split roadmap by lines
        lines = roadmap_text.split('\n')
        
        current_cve = None
        current_section = None
        
        # More flexible patterns to match:
        step_pattern = r'^(\d+(?:\.\d+)?)[\.\)]\s*(.+?)(?:\s*[-–]\s*(.+))?$'
        bullet_pattern = r'^[-*•]\s*(.+)$'  # Bullet points
        numbered_any_pattern = r'^(\d+(?:\.\d+)?)[\.\)\s]+(.+)$'  # More flexible numbered
        priority_pattern = r'\b(Critical|High|Medium|Low)\b'
        timeline_pattern = r'\b(Immediate|Short-term|Long-term|hours?|days?|weeks?|months?|ongoing)\b'
        
        # First pass: Identify section headers and CVE associations
        section_map = {}  # Map line indices to CVE-IDs
        for i, line in enumerate(lines):
            line_stripped = line.strip()
            if not line_stripped:
                continue
            
            line_upper = line_stripped.upper()
            
            # Check for section headers
            is_header = (line_stripped.startswith('#') or 
                        line_stripped.startswith('**') or
                        line_stripped.startswith('####'))
            
            if cve_ids and len(cve_ids) > 1:
                # Check for explicit CVE mentions in headers
                for cve_id in cve_ids:
                    if cve_id in line_upper:
                        section_map[i] = cve_id
                        break
                
                # Check for "Both", "All", "Common" keywords
                if any(keyword in line_upper for keyword in ['BOTH', 'ALL', 'COMMON', 'SHARED', 'UNIFIED']):
                    section_map[i] = 'BOTH'
        
        # Second pass: Extract steps with better CVE association
        for i, line in enumerate(lines):
            line_stripped = line.strip()
            if not line_stripped:
                continue
            
            line_upper = line_stripped.upper()
            
            # Update current section based on section map
            if i in section_map:
                current_section = section_map[i]
                current_cve = section_map[i]
            
            # Check if line mentions a CVE-ID
            if cve_ids and len(cve_ids) > 1:
                for cve_id in cve_ids:
                    if cve_id in line_upper and not any(char in line_stripped[:10] for char in ['|', '-']):  # Not a table row
                        current_cve = cve_id
                        current_section = cve_id
                        break
                
                if any(keyword in line_upper for keyword in ['BOTH', 'ALL', 'COMMON', 'SHARED']):
                    current_cve = 'BOTH'
                    current_section = 'BOTH'
            
            # Try multiple step patterns
            step_num = None
            action = None
            
            # Pattern 1: Standard numbered (1., 1.1, etc.)
            step_match = re.match(step_pattern, line_stripped, re.IGNORECASE)
            if step_match:
                step_num = step_match.group(1)
                action = step_match.group(2).strip()
            
            # Pattern 2: Bullet points
            if not action:
                bullet_match = re.match(bullet_pattern, line_stripped)
                if bullet_match:
                    action = bullet_match.group(1).strip()
                    # Generate step number based on position
                    if isinstance(result, dict):
                        target_cve = current_section or current_cve or cve_ids[0]
                        if target_cve in result:
                            step_num = str(len(result[target_cve]) + 1)
                    else:
                        step_num = str(len(result) + 1)
            
            # Pattern 3: More flexible numbered pattern
            if not action:
                numbered_match = re.match(numbered_any_pattern, line_stripped)
                if numbered_match:
                    step_num = numbered_match.group(1).strip()
                    action = numbered_match.group(2).strip()
            
            # If we found a step, process it
            if action:
                # Check if action mentions a specific CVE-ID
                action_upper = action.upper()
                step_cve = None
                
                if cve_ids and len(cve_ids) > 1:
                    # Check if action explicitly mentions a CVE-ID
                    for cve_id in cve_ids:
                        if cve_id in action_upper:
                            step_cve = cve_id
                            break
                    
                    # Check if action mentions "Both", "All", etc.
                    if any(keyword in action_upper for keyword in ['BOTH', 'ALL', 'COMMON', 'SHARED']):
                        step_cve = 'BOTH'
                    
                    # Use current section if no explicit CVE mentioned
                    if not step_cve:
                        if current_section and current_section != 'BOTH':
                            step_cve = current_section
                        elif current_cve and current_cve != 'BOTH':
                            step_cve = current_cve
                        else:
                            # Distribute to CVE with fewest steps
                            if isinstance(result, dict):
                                min_steps = min(len(result[cid]) for cid in cve_ids)
                                for cid in cve_ids:
                                    if len(result[cid]) == min_steps:
                                        step_cve = cid
                                        break
                            else:
                                step_cve = cve_ids[0]
                
                # Extract priority
                priority_match = re.search(priority_pattern, action, re.IGNORECASE)
                priority = priority_match.group(1) if priority_match else None
                
                # Extract timeline
                timeline_match = re.search(timeline_pattern, action, re.IGNORECASE)
                timeline = timeline_match.group(1) if timeline_match else None
                
                # Try to extract more detailed timeline
                if not timeline:
                    time_pattern = r'(\d+(?:-\d+)?\s*(?:hours?|days?|weeks?|months?))'
                    time_match = re.search(time_pattern, action, re.IGNORECASE)
                    if time_match:
                        timeline = time_match.group(1)
                
                # Clean action text
                clean_action = action
                if priority:
                    clean_action = re.sub(r'\b' + re.escape(priority) + r'\b', '', clean_action, flags=re.IGNORECASE).strip()
                if timeline and timeline in clean_action:
                    clean_action = re.sub(r'\b' + re.escape(timeline) + r'\b', '', clean_action, flags=re.IGNORECASE).strip()
                
                # Remove CVE-ID mentions from action for cleaner display
                if cve_ids:
                    for cve_id in cve_ids:
                        clean_action = re.sub(r'\b' + re.escape(cve_id) + r'\b', '', clean_action, flags=re.IGNORECASE).strip()
                    clean_action = re.sub(r'\b(BOTH|ALL|COMMON|SHARED)\b', '', clean_action, flags=re.IGNORECASE).strip()
                
                clean_action = re.sub(r'\s+', ' ', clean_action).strip(' ,-–')
                
                # Strip formatting prefixes that LLM might add (before checking metadata)
                formatting_prefixes = [
                    r'^\*\*action\*\*:?\s*',
                    r'^\*\*action:?\s*',
                    r'^\*action\*\*:?\s*',
                    r'^\*\*technical\s+recommendation\*\*:?\s*',
                    r'^\*\*technical\s+recommendation:?\s*',
                    r'^\*\*details\*\*:?\s*',
                    r'^\*\*details:?\s*',
                    r'^\*\*timeline\*\*:?\s*',
                    r'^\*timeline\*\*:?\s*',
                    r'^\*\*priority\*\*:?\s*',
                    r'^\*\*priority:?\s*',
                ]
                for prefix_pattern in formatting_prefixes:
                    clean_action = re.sub(prefix_pattern, '', clean_action, flags=re.IGNORECASE).strip()
                
                # Skip timeline-only lines (lines that are just timeline metadata)
                if re.match(r'^[\*\s]*timeline[\*\s]*:?[\*\s]*\(?[\d\s-]+(?:day|week|month|hour)', clean_action, re.IGNORECASE):
                    continue
                
                # Skip label-only lines (lines that are just formatting labels)
                if re.match(r'^[\*\s]*(?:action|technical\s+recommendation|details|priority|mitigation\s+strategies?)[\*\s]*:?\s*$', clean_action, re.IGNORECASE):
                    continue
                
                # Filter out metadata/formatting lines
                # Skip lines that are just labels, formatting, or empty
                if clean_action:
                    # Check for common metadata patterns
                    metadata_patterns = [
                        r'^\*?\*?priority\s*level\*?\*?:?\*?\*?$',
                        r'^\*?\*?timeline\*?\*?:?\*?\*?$',
                        r'^\*?\*?actions?\*?\*?:?\*?\*?$',
                        r'^\*?\*?:?\*?\*?$',  # Just asterisks/colons
                        r'^[-*•\s:]+$',  # Just formatting characters
                        r'^\*\*mitigation\s*strategies?\*\*$',
                        r'^regular\s*updates?:?$',
                        r'^code\s*reviews?:?$',
                        r'^security\s*training?:?$',
                    ]
                    
                    is_metadata = False
                    clean_upper = clean_action.upper()
                    for pattern in metadata_patterns:
                        if re.match(pattern, clean_upper, re.IGNORECASE):
                            is_metadata = True
                            break
                    
                    # Also check if action is too short or just punctuation
                    if not is_metadata and len(clean_action) > 10 and not re.match(r'^[^\w\s]+$', clean_action):
                        step_data = {
                            'step': step_num or '1',
                            'action': clean_action,
                            'priority': priority or 'Medium',
                            'timeline': timeline or 'Not specified'
                        }
                        
                        if isinstance(result, dict):
                            if step_cve:
                                result[step_cve].append(step_data)
                            elif current_cve:
                                result[current_cve].append(step_data)
                            else:
                                # Distribute to CVE with fewest steps
                                min_steps = min(len(result[cid]) for cid in cve_ids)
                                for cid in cve_ids:
                                    if len(result[cid]) == min_steps:
                                        result[cid].append(step_data)
                                        break
                        else:
                            result.append(step_data)
        
        # Enhanced fallback: If some CVEs have no steps, try to extract from entire text
        if isinstance(result, dict) and cve_ids and len(cve_ids) > 1:
            empty_cves = [cid for cid in cve_ids if len(result.get(cid, [])) == 0]
            
            if empty_cves:
                # Try to find any numbered items and assign to empty CVEs
                for line in lines:
                    line_stripped = line.strip()
                    if not line_stripped or line_stripped.startswith('#'):
                        continue
                    
                    # Look for any numbered pattern
                    numbered_match = re.match(r'^(\d+(?:\.\d+)?)[\.\)\s]+(.+)$', line_stripped)
                    if numbered_match:
                        step_num = numbered_match.group(1)
                        action = numbered_match.group(2).strip()
                        
                        # Skip if too short or looks like a header
                        if len(action) < 10:
                            continue
                        
                        # Check if this step mentions any of the empty CVEs
                        action_upper = action.upper()
                        assigned = False
                        
                        for cve_id in empty_cves:
                            if cve_id in action_upper:
                                priority = None
                                timeline = None
                                
                                priority_match = re.search(priority_pattern, action, re.IGNORECASE)
                                if priority_match:
                                    priority = priority_match.group(1)
                                
                                timeline_match = re.search(timeline_pattern, action, re.IGNORECASE)
                                if timeline_match:
                                    timeline = timeline_match.group(1)
                                
                                # Clean action
                                clean_action = action
                                if priority:
                                    clean_action = re.sub(r'\b' + re.escape(priority) + r'\b', '', clean_action, flags=re.IGNORECASE).strip()
                                if timeline:
                                    clean_action = re.sub(r'\b' + re.escape(timeline) + r'\b', '', clean_action, flags=re.IGNORECASE).strip()
                                
                                for cid in cve_ids:
                                    clean_action = re.sub(r'\b' + re.escape(cid) + r'\b', '', clean_action, flags=re.IGNORECASE).strip()
                                
                                clean_action = re.sub(r'\s+', ' ', clean_action).strip(' ,-–')
                                
                                # Strip formatting prefixes (same as main parsing)
                                formatting_prefixes = [
                                    r'^\*\*action\*\*:?\s*',
                                    r'^\*\*action:?\s*',
                                    r'^\*action\*\*:?\s*',
                                    r'^\*\*technical\s+recommendation\*\*:?\s*',
                                    r'^\*\*technical\s+recommendation:?\s*',
                                    r'^\*\*details\*\*:?\s*',
                                    r'^\*\*details:?\s*',
                                    r'^\*\*timeline\*\*:?\s*',
                                    r'^\*timeline\*\*:?\s*',
                                    r'^\*\*priority\*\*:?\s*',
                                    r'^\*\*priority:?\s*',
                                ]
                                for prefix_pattern in formatting_prefixes:
                                    clean_action = re.sub(prefix_pattern, '', clean_action, flags=re.IGNORECASE).strip()
                                
                                # Skip timeline-only lines
                                if re.match(r'^[\*\s]*timeline[\*\s]*:?[\*\s]*\(?[\d\s-]+(?:day|week|month|hour)', clean_action, re.IGNORECASE):
                                    continue
                                
                                # Skip label-only lines
                                if re.match(r'^[\*\s]*(?:action|technical\s+recommendation|details|priority|mitigation\s+strategies?)[\*\s]*:?\s*$', clean_action, re.IGNORECASE):
                                    continue
                                
                                # Apply same filtering as main parsing
                                if clean_action and len(clean_action) > 10:
                                    # Check for metadata patterns
                                    metadata_patterns = [
                                        r'^\*?\*?priority\s*level\*?\*?:?\*?\*?$',
                                        r'^\*?\*?timeline\*?\*?:?\*?\*?$',
                                        r'^\*?\*?actions?\*?\*?:?\*?\*?$',
                                        r'^\*?\*?:?\*?\*?$',
                                        r'^[-*•\s:]+$',
                                    ]
                                    
                                    is_metadata = False
                                    clean_upper = clean_action.upper()
                                    for pattern in metadata_patterns:
                                        if re.match(pattern, clean_upper, re.IGNORECASE):
                                            is_metadata = True
                                            break
                                    
                                    if not is_metadata and not re.match(r'^[^\w\s]+$', clean_action):
                                        result[cve_id].append({
                                            'step': step_num,
                                            'action': clean_action,
                                            'priority': priority or 'Medium',
                                            'timeline': timeline or 'Not specified'
                                        })
                                    assigned = True
                                    empty_cves = [cid for cid in cve_ids if len(result.get(cid, [])) == 0]
                                    if not empty_cves:
                                        break
                                    break
                        
                        if not empty_cves:
                            break
        
        # Clean up: remove 'BOTH' key if empty, or distribute its steps to all CVEs
        if isinstance(result, dict) and 'BOTH' in result:
            if len(result['BOTH']) > 0:
                # Distribute "BOTH" steps to all CVEs
                for cve_id in cve_ids:
                    result[cve_id].extend(result['BOTH'])
            del result['BOTH']
        
        return result if (isinstance(result, dict) and any(len(v) > 0 for v in result.values())) or \
                         (isinstance(result, list) and len(result) > 0) else None
    
    def _create_steps_table(self, parsed_steps, cve_ids=None):
        """
        Create a formatted list of mitigation steps (no table, no timeline).
        Ensures all CVEs get their own section.
        
        Args:
            parsed_steps: Dict with CVE-ID as key and list of steps, or list of steps
            cve_ids: List of CVE-IDs (for organization)
        
        Returns:
            Formatted list string
        """
        if not parsed_steps:
            return None
        
        steps_output = "\nMITIGATION STEPS:\n"
        steps_output += "-"*80 + "\n"
        
        # If multiple CVEs, organize by CVE - show ALL CVEs even if some have no steps
        if isinstance(parsed_steps, dict) and cve_ids and len(cve_ids) > 1:
            for cve_id in cve_ids:
                # Always show section for each CVE, even if empty
                steps_output += f"\n{cve_id}:\n"
                
                if cve_id in parsed_steps and len(parsed_steps[cve_id]) > 0:
                    # Renumber steps sequentially starting from 1
                    for idx, step in enumerate(parsed_steps[cve_id], start=1):
                        action = step.get('action', 'N/A')
                        priority = step.get('priority', 'Medium')
                        
                        # Format: "1. [Priority] Action text"
                        steps_output += f"  {idx}. [{priority}] {action}\n"
                else:
                    # Show message if no steps found for this CVE
                    steps_output += "  No specific steps found for this CVE.\n"
                
                steps_output += "\n"
        else:
            # Single CVE or unified steps
            steps_list = parsed_steps if isinstance(parsed_steps, list) else \
                        (list(parsed_steps.values())[0] if isinstance(parsed_steps, dict) else [])
            
            if steps_list:
                # Renumber steps sequentially starting from 1
                for idx, step in enumerate(steps_list, start=1):
                    action = step.get('action', 'N/A')
                    priority = step.get('priority', 'Medium')
                    
                    # Format: "1. [Priority] Action text"
                    steps_output += f"  {idx}. [{priority}] {action}\n"
                
                steps_output += "\n"
        
        return steps_output
    
    def _generate_short_summary(self, cve_ids, cve_dfs, parsed_steps):
        """
        Generate a short 1-paragraph summary of the mitigation roadmap.
        
        Args:
            cve_ids: List of CVE-IDs
            cve_dfs: List of DataFrames with CVE details
            parsed_steps: Parsed steps data
        
        Returns:
            Short summary paragraph string
        """
        try:
            # Count steps by priority
            critical_count = 0
            high_count = 0
            medium_count = 0
            
            if isinstance(parsed_steps, dict):
                for cve_id, steps in parsed_steps.items():
                    for step in steps:
                        priority = step.get('priority', '').lower()
                        if 'critical' in priority:
                            critical_count += 1
                        elif 'high' in priority:
                            high_count += 1
                        elif 'medium' in priority:
                            medium_count += 1
            elif isinstance(parsed_steps, list):
                for step in parsed_steps:
                    priority = step.get('priority', '').lower()
                    if 'critical' in priority:
                        critical_count += 1
                    elif 'high' in priority:
                        high_count += 1
                    elif 'medium' in priority:
                        medium_count += 1
            
            # Get CVE titles for summary
            cve_titles = []
            for cve_df in cve_dfs:
                if cve_df is not None and len(cve_df) > 0:
                    title = cve_df.iloc[0].get('title', 'Unknown')
                    if title and title != 'Unknown':
                        cve_titles.append(title)
            
            # Build summary
            summary_parts = []
            
            if len(cve_ids) == 1:
                summary_parts.append(f"This mitigation plan for {cve_ids[0]}")
            else:
                summary_parts.append(f"This mitigation plan for {len(cve_ids)} CVEs ({', '.join(cve_ids)})")
            
            if critical_count > 0:
                summary_parts.append(f"includes {critical_count} critical action(s) requiring immediate attention")
            
            if high_count > 0:
                summary_parts.append(f"{high_count} high-priority action(s) for short-term fixes")
            
            if medium_count > 0:
                summary_parts.append(f"and {medium_count} medium-priority action(s) for long-term prevention")
            
            summary_parts.append("as outlined above. Organizations should prioritize critical actions first, followed by high-priority patches and updates, then implement long-term security improvements to prevent similar vulnerabilities.")
            
            summary = " ".join(summary_parts) + "."
            
            return summary
            
        except Exception as e:
            # Fallback summary
            if len(cve_ids) == 1:
                return f"This mitigation plan provides actionable steps to address {cve_ids[0]}. Follow the priority levels outlined above to effectively mitigate the vulnerability."
            else:
                return f"This mitigation plan provides actionable steps to address {len(cve_ids)} CVEs ({', '.join(cve_ids)}). Follow the priority levels outlined above to effectively mitigate these vulnerabilities."

    def generate_mitigation_roadmap(self, cve_id_or_text, question=None):
        """
        Main method: Get CVE details and generate mitigation roadmap.
        Supports multiple CVE-IDs in a single request.
        
        Args:
            cve_id_or_text: CVE identifier(s) (e.g., "CVE-2024-1234") or text containing CVE-ID(s)
            question: Optional follow-up question about the mitigation
        
        Returns:
            dict with 'cve_ids', 'cve_details', 'roadmap', 'steps', 'formatted_output'
        """
        # Extract ALL CVE-IDs from input
        extracted_cve_ids = self._extract_cve_ids(cve_id_or_text)
        
        if not extracted_cve_ids:
            # If no CVE-ID found, check if it's a pure CVE-ID format
            if re.match(r'^CVE-\d{4}-\d{4,7}$', cve_id_or_text.upper()):
                extracted_cve_ids = [cve_id_or_text.upper().strip()]
            else:
                return {
                    "cve_ids": [],
                    "cve_details": None,
                    "roadmap": None,
                    "steps": None,
                    "formatted_output": f"Could not extract CVE-ID from: '{cve_id_or_text}'. Please provide a valid CVE-ID (e.g., CVE-2024-1234).",
                    "error": "CVE-ID not found"
                }
        
        # If question is None but input contains text after CVE-IDs, extract it as question
        if question is None:
            # Remove all CVE-IDs from input to get remaining text
            remaining_text = cve_id_or_text
            for cve_id in extracted_cve_ids:
                remaining_text = remaining_text.replace(cve_id, '', 1)
            remaining_text = re.sub(r'^[,;\s]+|[,;\s]+$', '', remaining_text.strip())
            if remaining_text:
                question = remaining_text
        
        cve_ids = extracted_cve_ids
        
        # Step 1: Get CVE details from database for all CVEs
        cve_dfs = []
        found_cve_ids = []
        
        for cve_id in cve_ids:
            cve_df = self.get_cve_by_id(cve_id)
            if cve_df is not None:
                cve_dfs.append(cve_df)
                found_cve_ids.append(cve_id)
            else:
                print(f"[WARNING] CVE-ID '{cve_id}' not found in database, skipping...")
        
        if not cve_dfs:
            return {
                "cve_ids": cve_ids,
                "cve_details": None,
                "roadmap": None,
                "steps": None,
                "formatted_output": f"None of the provided CVE-IDs were found in database: {', '.join(cve_ids)}",
                "error": "CVEs not found"
            }
        
        # Step 2: Format CVE info for LLM (all CVEs)
        cve_info = self._format_cves_for_llm(cve_dfs)
        
        # Step 3: Generate roadmap using LLM
        if question:
            # If there's a follow-up question, add it to the prompt
            roadmap = self._generate_roadmap_with_llm(cve_info + f"\n\nFollow-up question: {question}", found_cve_ids)
        else:
            roadmap = self._generate_roadmap_with_llm(cve_info, found_cve_ids)
        
        # Step 4: Parse roadmap into structured steps
        steps = self._parse_roadmap_steps(roadmap, found_cve_ids)
        
        # Step 5: Create formatted output (pass steps for table generation)
        formatted_output = self._create_formatted_output(found_cve_ids, cve_dfs, roadmap, steps)
        
        # Store in conversation history
        self.conversation_history.append({
            "cve_ids": found_cve_ids,
            "question": question or f"Generate mitigation roadmap for {', '.join(found_cve_ids)}",
            "answer": roadmap
        })
        
        # Store previous CVEs for follow-ups
        self.previous_cve = cve_dfs[0] if len(cve_dfs) == 1 else cve_dfs
        
        return {
            "cve_ids": found_cve_ids,
            "cve_details": cve_dfs,
            "roadmap": roadmap,
            "steps": steps,
            "formatted_output": formatted_output
        }
    
    def _create_formatted_output(self, cve_ids, cve_dfs, roadmap, parsed_steps=None):
        """
        Create a nicely formatted output string for one or more CVEs.
        Simplified to show only Overview, Mitigation Steps, and Summary.
        
        Args:
            cve_ids: Single CVE-ID string or list of CVE-IDs
            cve_dfs: Single DataFrame or list of DataFrames with CVE details
            roadmap: Generated roadmap text (not used in output, but kept for history)
            parsed_steps: Parsed steps data for steps list generation
        
        Returns:
            Formatted string
        """
        # Handle single CVE for backward compatibility
        if isinstance(cve_ids, str):
            cve_ids = [cve_ids]
        if isinstance(cve_dfs, pd.DataFrame):
            cve_dfs = [cve_dfs]
        
        output = ""  # Start with empty string - no CVE-IDs header or OVERVIEW section
        
        # Go directly to mitigation steps
        output += "\n" + "="*80 + "\n"
        
        # If multiple CVEs, organize by CVE - show ALL CVEs even if some have no steps
        if isinstance(parsed_steps, dict) and cve_ids and len(cve_ids) > 1:
            for cve_id in cve_ids:
                # Always show section for each CVE, even if empty
                output += f"\n{cve_id}:\n"
                
                if cve_id in parsed_steps and len(parsed_steps[cve_id]) > 0:
                    # Renumber steps sequentially starting from 1
                    for idx, step in enumerate(parsed_steps[cve_id], start=1):
                        action = step.get('action', 'N/A')
                        priority = step.get('priority', 'Medium')
                        
                        # Format: "1. [Priority] Action text"
                        output += f"  {idx}. [{priority}] {action}\n"
                else:
                    # Show message if no steps found for this CVE
                    output += "  No specific steps found for this CVE.\n"
                
                output += "\n"
        else:
            # Single CVE or unified steps
            steps_list = parsed_steps if isinstance(parsed_steps, list) else \
                        (list(parsed_steps.values())[0] if isinstance(parsed_steps, dict) else [])
            
            if steps_list:
                # Renumber steps sequentially starting from 1
                for idx, step in enumerate(steps_list, start=1):
                    action = step.get('action', 'N/A')
                    priority = step.get('priority', 'Medium')
                    
                    # Format: "1. [Priority] Action text"
                    output += f"  {idx}. [{priority}] {action}\n"
                
                output += "\n"
        
        output += "\n" + "="*80 + "\n"
        
        # Add short summary instead of detailed roadmap
        if parsed_steps:
            summary = self._generate_short_summary(cve_ids, cve_dfs, parsed_steps)
            output += "SUMMARY:\n"
            output += "-"*80 + "\n"
            output += summary + "\n"
            output += "\n" + "="*80 + "\n"
        else:
            # Fallback if no parsed steps
            output += "SUMMARY:\n"
            output += "-"*80 + "\n"
            if len(cve_ids) == 1:
                output += f"Mitigation steps for {cve_ids[0]} are outlined above. Follow the priority levels to effectively address this vulnerability.\n"
            else:
                output += f"Mitigation steps for {len(cve_ids)} CVEs ({', '.join(cve_ids)}) are outlined above. Follow the priority levels to effectively address these vulnerabilities.\n"
            output += "\n" + "="*80 + "\n"
        
        return output
    
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
        self.previous_cve = None


if __name__ == "__main__":
    # Test the Risk Mitigation Agent
    print("="*80)
    print("RISK MITIGATION AGENT - TEST")
    print("="*80)
    print("\nThis agent generates mitigation roadmaps for specific CVE-IDs.")
    print("Enter a CVE-ID (e.g., CVE-2024-1234) to get a mitigation roadmap.")
    print("Type 'quit', 'exit', or 'q' to stop.")
    print("Type 'clear' or 'reset' to clear conversation history.")
    print("-"*80)
    
    # Initialize agent
    agent = RiskMitigationAgent(provider="openai", model="gpt-4o-mini")
    
    current_cve_id = None
    
    while True:
        try:
            # Get user input
            user_input = input("\nEnter CVE-ID or question: ").strip()
            
            if user_input.lower() in ['quit', 'exit', 'q']:
                print("\nGoodbye!")
                break
            
            if user_input.lower() in ['clear', 'reset']:
                agent.clear_history()
                current_cve_id = None
                print("\n[INFO] Conversation history cleared.\n")
                continue
            
            if not user_input:
                continue
            
            # Extract ALL CVE-IDs from input (even if there are extra words)
            extracted_cve_ids = agent._extract_cve_ids(user_input)
            
            if extracted_cve_ids:
                # CVE-ID(s) found in input
                # Extract question part if any
                remaining_text = user_input
                for cve_id in extracted_cve_ids:
                    remaining_text = remaining_text.replace(cve_id, '', 1)
                remaining_text = re.sub(r'^[,;\s]+|[,;\s]+$', '', remaining_text.strip())
                question = remaining_text if remaining_text else None
                
                result = agent.generate_mitigation_roadmap(user_input, question=question)
                
                # Display formatted output
                print("\n" + result['formatted_output'])
                
                # Update current_cve_id for follow-ups (use first one)
                if result.get('cve_ids'):
                    current_cve_id = result['cve_ids'][0] if len(result['cve_ids']) == 1 else result['cve_ids']
                
            elif current_cve_id:
                # Follow-up question about current CVE (no CVE-ID in this input)
                if isinstance(current_cve_id, list):
                    result = agent.generate_mitigation_roadmap(', '.join(current_cve_id), question=user_input)
                else:
                    result = agent.generate_mitigation_roadmap(current_cve_id, question=user_input)
                print("\n" + result['formatted_output'])
            else:
                # No CVE-ID found and no current CVE
                print("\n[INFO] Please provide a CVE-ID (e.g., CVE-2024-1234)")
                print("You can provide multiple CVEs: 'CVE-2024-50603, CVE-2024-57937 give me mitigation plan'")
            
            print("\n" + "-"*80)
            
        except KeyboardInterrupt:
            print("\n\n[INFO] Interrupted by user")
            break
        except Exception as e:
            print(f"\n[ERROR] An error occurred: {e}")
            import traceback
            traceback.print_exc()
            print("\n" + "-"*80)

