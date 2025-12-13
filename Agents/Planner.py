import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import os
import re
import json
import pandas as pd
from dotenv import load_dotenv

load_dotenv()

# Add this import
from langchain_openai import ChatOpenAI

from Agents.image_reading_agent import TechStackDetectionAgent
from Agents.cve_search_agent import CVESearchAgent
from Agents.risk_assessment_agent import RiskAssessmentAgent
from Agents.risk_mitigation_agent import RiskMitigationAgent
from Agents.report_generation_agent import ReportGenerationAgent


class PlannerAgent:
    """
    Conversational orchestrator agent that routes user input to appropriate specialized agents.
    Maintains conversation context and supports step-by-step, back-and-forth interactions.
    
    Features:
    - One agent at a time (user-driven, not automatic pipeline)
    - Conversation memory (remembers previous agent outputs)
    - Context-aware routing (uses previous outputs for next steps)
    - Back-and-forth flexibility (can ask follow-ups, go back, jump around)
    """
    
    def __init__(self, provider="openai"):
        """
        Initialize Planner Agent with specialized agents and dual memory system.
        """
        self.provider = provider
        
        # Initialize LLM for query classification
        self.llm = ChatOpenAI(
            model_name="gpt-4o-mini",
            temperature=0.1,
            provider=provider
        )
        
        # Initialize all specialized agents
        self.tech_stack_agent = TechStackDetectionAgent()
        self.cve_search_agent = CVESearchAgent(top_k=10, provider=provider)
        self.risk_assessment_agent = RiskAssessmentAgent(provider=provider)
        self.risk_mitigation_agent = RiskMitigationAgent(provider=provider)
        self.report_generation_agent = ReportGenerationAgent()
        
        # DUAL MEMORY SYSTEM
        # Memory 1: Image-based context (from tech stack detection)
        self.image_context = {
            "tech_stack": None,           # From TechStackDetectionAgent
            "cves": None,                  # CVEs for image tech stack
            "risk_assessment": None,       # Risk assessment for image tech stack
            "mitigation": None,            # Mitigation for image tech stack
            "last_agent": None,
            "last_output": None,
        }
        
        # Memory 2: Text-based context (from random prompts)
        self.text_context = {
            "cves": None,                  # CVEs from text searches
            "risk_assessment": None,       # Risk assessment from text queries
            "mitigation": None,            # Mitigation from text queries
            "last_agent": None,
            "last_output": None,
            "last_search_term": None,      # Last technology/search term used
        }
        
        # Legacy conversation_context for backward compatibility
        self.conversation_context = {
            "tech_stack": None,
            "cves": None,
            "risk_assessment": None,
            "mitigation": None,
            "last_agent": None,
            "last_output": None,
            "conversation_history": []
        }
    
    def _detect_context_type(self, user_input):
        """
        Detect if the prompt is related to image-based context or text-based context.
        Uses LLM-based parsing with keyword fallback.
        
        Returns:
            "image" - if query is about image-detected tech stack
            "text" - if query is about a new text-based search
        """
        if not user_input:
            return "text"
        
        try:
            # Try LLM-based parsing first
            parsed = self._parse_query_with_llm(user_input)
            context_type = parsed.get('context_type', 'auto')
            
            # If LLM says "auto", use fallback logic
            if context_type == 'auto':
                return self._detect_context_type_keyword_fallback(user_input)
            
            # Validate context type
            if context_type in ['image', 'text']:
                return context_type
            else:
                return self._detect_context_type_keyword_fallback(user_input)
        except Exception as e:
            print(f"[WARNING] Context type detection failed, using keyword fallback: {e}")
            return self._detect_context_type_keyword_fallback(user_input)
    
    def _detect_context_type_keyword_fallback(self, user_input):
        """
        Original keyword-based context detection (fallback).
        This is the EXACT current implementation with expanded keywords.
        """
        input_lower = user_input.lower()
        
        # Keywords that indicate image-based context (EXPANDED)
        image_context_keywords = [
            'my stack', 'the stack', 'this stack', 'that stack',
            'detected technologies', 'from the image', 'from image',
            'my tech stack', 'the tech stack', 'these technologies',
            'those technologies', 'all the technologies', 'the technologies',
            'previous', 'returned', 'detected',
            'above techstack', 'above tech stack', 'above stack',
            'in above', 'for above', 'the above', 'above mentioned',
            'above', 'above cves', 'above vulnerabilities',  # ADDED
            'these cves', 'those cves', 'mentioned cves',  # ADDED
            'these vulnerabilities', 'those vulnerabilities'  # ADDED
        ]
        
        # Check if query mentions image-based tech stack
        has_image_context = any(keyword in input_lower for keyword in image_context_keywords)
        
        # Check if we have image context with tech stack
        has_image_tech_stack = self.image_context.get('tech_stack') is not None
        
        # If query explicitly mentions image context AND we have image tech stack
        if has_image_context and has_image_tech_stack:
            return "image"
        
        # If query mentions a specific technology name (not in image context)
        # Check if it's a new search term
        if not has_image_context:
            # Check if it's asking about a specific tech that's not in image context
            if has_image_tech_stack:
                image_tech_stack_lower = [t.lower() for t in self.image_context['tech_stack']]
                # Extract potential tech name from query
                words = input_lower.split()
                for word in words:
                    word_clean = re.sub(r'[^\w]', '', word)
                    if (word_clean and len(word_clean) > 2 and 
                        word_clean not in ['cve', 'cves', 'for', 'in', 'the', 'my', 'all', 'give', 'me', 'show', 'tell'] and
                        word_clean not in image_tech_stack_lower):
                        # This is likely a new text-based search
                        return "text"
        
        # Default: use text context for new queries
        return "text"
    
    def _get_active_context(self, context_type):
        """
        Get the active context based on context type.
        
        Args:
            context_type: "image" or "text"
        
        Returns:
            The appropriate context dictionary
        """
        if context_type == "image":
            return self.image_context
        else:
            return self.text_context
    
    def _update_context(self, context_type, updates):
        """
        Update the appropriate context with new data.
        
        Args:
            context_type: "image" or "text"
            updates: Dictionary of updates to apply
        """
        context = self._get_active_context(context_type)
        context.update(updates)
        
        # Also update legacy conversation_context for backward compatibility
        if context_type == "image":
            self.conversation_context['tech_stack'] = context.get('tech_stack')
        else:
            # For text context, clear tech_stack (text context doesn't have tech_stack)
            self.conversation_context['tech_stack'] = None
        
        self.conversation_context.update({
            'cves': context.get('cves'),
            'risk_assessment': context.get('risk_assessment'),
            'mitigation': context.get('mitigation'),
            'last_agent': context.get('last_agent'),
            'last_output': context.get('last_output')
        })
    
    def _route_to_tech_stack_detection(self, image_path):
        """
        Route to Tech Stack Detection Agent - PURE ROUTING.
        Updates IMAGE context.
        """
        # Normalize path
        image_path = os.path.normpath(image_path.strip().strip('"').strip("'"))
        
        # Call agent
        tech_result = self.tech_stack_agent.detect_tech_stack(image_path)
        
        # Extract clean tech stack
        clean_tech_stack = self._extract_clean_tech_stack_from_output(tech_result)
        
        # Update IMAGE context
        self._update_context("image", {
            'tech_stack': clean_tech_stack,
            'last_agent': 'TechStackDetectionAgent',
            'last_output': tech_result
        })
        
        # Format output
        output = "\n" + "="*80 + "\n"
        output += "TECH STACK DETECTION\n"
        output += "="*80 + "\n\n"
        output += f"Detected Technologies: {', '.join(clean_tech_stack) if clean_tech_stack else 'None'}\n"
        output += f"Total: {len(clean_tech_stack)} technologies\n\n"
        
        if tech_result.get('details'):
            details = tech_result['details']
            
            # Remove redundant "TECHNOLOGIES:" section from details
            # The details typically contains: "TECHNOLOGIES: ... \n\n DETAILS: ..."
            # We only want to show the DETAILS part since we already show "Detected Technologies" at top
            
            # Split by "DETAILS:" to get only the details section
            if "DETAILS:" in details.upper():
                # Extract everything after "DETAILS:"
                parts = re.split(r'DETAILS:\s*', details, flags=re.IGNORECASE)
                if len(parts) > 1:
                    # Use only the content after "DETAILS:"
                    details_content = parts[1].strip()
                else:
                    # If split didn't work, try removing TECHNOLOGIES section
                    details_content = re.sub(r'TECHNOLOGIES:.*?(?=DETAILS:|$)', '', details, flags=re.DOTALL | re.IGNORECASE).strip()
            else:
                # No "DETAILS:" marker, remove TECHNOLOGIES section if present
                details_content = re.sub(r'TECHNOLOGIES:.*?\n', '', details, flags=re.IGNORECASE)
                details_content = details_content.strip()
            
            # Only add if there's meaningful content left (more than just whitespace)
            if details_content and len(details_content) > 20:
                output += "Details:\n"
                output += "-"*80 + "\n"
                output += details_content + "\n"
        
        output += "\n" + "="*80 + "\n"
        
        return {
            "status": "success",
            "agent": "TechStackDetectionAgent",
            "result": tech_result,
            "output": output,
            "tech_stack": clean_tech_stack
        }
    
    def _route_to_cve_search(self, user_input):
        """
        Route to CVE Search Agent - PURE ROUTING.
        Detects context type and updates appropriate memory.
        """
        input_lower = user_input.lower()
        
        # Detect which context to use
        context_type = self._detect_context_type(user_input)
        active_context = self._get_active_context(context_type)
        
        # Check if user is asking for CVEs for image tech stack
        # EXPANDED to catch more variations like "above techstack", "above tech stack", etc.
        is_asking_for_image_stack = (
            context_type == "image" and 
            any(phrase in input_lower for phrase in [
                'previous', 'returned', 'detected', 'these technologies', 
                'those technologies', 'all the technologies', 'the technologies',
                'technology stack', 'tech stack', 'techstack', 'the techstack', 
                'for these', 'for those', 'for the techstack', 'for the tech stack',
                'my stack', 'in my stack', 'for my stack', 'from my stack',
                'the stack', 'in the stack', 'for the stack', 'from the stack',
                'this stack', 'in this stack', 'for this stack', 'from this stack',
                'that stack', 'in that stack', 'for that stack',
                'above techstack', 'above tech stack', 'above stack',  # Catch "above" variations
                'in above', 'for above', 'the above', 'above mentioned'  # Catch "above" references
            ])
        )
        
        # Check if user is asking about something SPECIFIC (not generic)
        # IMPORTANT: Don't treat "above techstack" as a specific search term
        has_specific_search_term = False
        specific_patterns = [' in ', ' for ', ' about ', ' related to ']
        generic_words = ['the', 'these', 'those', 'all', 'my', 'our', 'your', 'their', 'this', 'that']
        # Add tech stack reference words to generic_words
        tech_stack_reference_words = [
            'above techstack', 'above tech stack', 'above stack', 'above',
            'techstack', 'tech stack', 'stack', 'technologies', 'technology'
        ]
        generic_words.extend(tech_stack_reference_words)
        
        for pattern in specific_patterns:
            if pattern in input_lower:
                parts = input_lower.split(pattern, 1)
                if len(parts) > 1:
                    after_pattern = parts[1].strip()
                    after_pattern = re.sub(r'\s+(cves?|vulnerabilities?|issues?|problems?)$', '', after_pattern)
                    # Check if it's a tech stack reference (should NOT be treated as specific search term)
                    is_tech_stack_ref = any(ref in after_pattern for ref in tech_stack_reference_words)
                    if after_pattern and after_pattern not in generic_words and len(after_pattern) > 2 and not is_tech_stack_ref:
                        has_specific_search_term = True
                        break
        
        # Use image tech stack ONLY if explicitly asking for it
        if context_type == "image" and is_asking_for_image_stack and not has_specific_search_term:
            # Use image context tech stack
            tech_stack = active_context.get('tech_stack')
            if tech_stack:
                print(f"\n[INFO] Routing to tech stack CVE search for {len(tech_stack)} technologies...")
                result = self.cve_search_agent.search_cves_for_tech_stack(
                    tech_stack=tech_stack,
                    top_k_per_tech=None
                )
                formatted_output = self._format_tech_stack_cve_output(result)
                
                # Update IMAGE context
                self._update_context("image", {
                    'cves': result.get('cves'),
                    'last_agent': 'CVESearchAgent',
                    'last_output': result
                })
            else:
                # No tech stack in image context
                result = self.cve_search_agent.search_cves(query=user_input)
                formatted_output = result.get('answer', '')
                
                # Update TEXT context
                self._update_context("text", {
                    'cves': result.get('cves'),
                    'last_agent': 'CVESearchAgent',
                    'last_output': result,
                    'last_search_term': self._extract_search_term(user_input)
                })
        else:
            # Use regular search (text context)
            result = self.cve_search_agent.search_cves(query=user_input)
            formatted_output = result.get('answer', '')
            
            # Update TEXT context
            self._update_context("text", {
                'cves': result.get('cves'),
                'last_agent': 'CVESearchAgent',
                'last_output': result,
                'last_search_term': self._extract_search_term(user_input)
            })
        
        # Add to conversation history
        self.conversation_context['conversation_history'].append({
            "input": user_input,
            "agent": "CVESearchAgent",
            "output": result
        })
        
        return {
            "status": "success",
            "agent": "CVESearchAgent",
            "result": result,
            "output": formatted_output
        }
    
    def _extract_search_term(self, user_input):
        """
        Extract the main search term from user input.
        Uses LLM-based parsing with keyword fallback.
        """
        if not user_input:
            return None
        
        try:
            # Try LLM-based parsing first
            parsed = self._parse_query_with_llm(user_input)
            search_query = parsed.get('search_query', '')
            
            if search_query:
                # Remove "vulnerabilities" suffix if present (will be added by agent)
                search_query = search_query.replace(' vulnerabilities', '').replace(' vulnerability', '').strip()
                return search_query if search_query else None
            else:
                # Fallback to keyword-based extraction
                return self._extract_search_term_keyword_fallback(user_input)
        except Exception as e:
            print(f"[WARNING] Search term extraction failed, using keyword fallback: {e}")
            return self._extract_search_term_keyword_fallback(user_input)
    
    def _extract_search_term_keyword_fallback(self, user_input):
        """
        Original keyword-based search term extraction (fallback).
        This is the EXACT current implementation.
        """
        input_lower = user_input.lower()
        
        # Remove common query words
        words = input_lower.split()
        filtered_words = [w for w in words if w not in [
            'cve', 'cves', 'vulnerability', 'vulnerabilities', 'for', 'in', 'about',
            'the', 'my', 'all', 'give', 'me', 'show', 'tell', 'what', 'are', 'is'
        ]]
        
        if filtered_words:
            return ' '.join(filtered_words[:3])  # Take first few words
        return None
    
    def _parse_query_with_llm(self, user_input):
        """
        Use LLM to dynamically parse natural language queries.
        Extracts technology names, intent, and context references.
        
        Args:
            user_input: User's natural language query
            
        Returns:
            dict with:
            - 'intent': 'cve_search', 'risk_assessment', 'mitigation', etc.
            - 'technologies': list of extracted technology/product names
            - 'is_reference': bool - whether query references previous results
            - 'context_type': 'image' or 'text' or 'auto'
            - 'search_query': str - cleaned search query for CVE search
        """
        if not user_input or not user_input.strip():
            return self._parse_query_fallback(user_input)
        
        try:
            # Build context summary for LLM
            image_tech_stack = self.image_context.get('tech_stack', [])
            text_last_search = self.text_context.get('last_search_term')
            
            context_summary = f"""Available Context:
- Image tech stack: {', '.join(image_tech_stack) if image_tech_stack else 'None'}
- Image last agent: {self.image_context.get('last_agent') or 'None'}
- Text last search: {text_last_search or 'None'}
- Text last agent: {self.text_context.get('last_agent') or 'None'}"""
            
            # Create prompt for LLM
            prompt = f"""You are a cybersecurity query analyzer. Analyze this user query and extract structured information.

User Query: "{user_input}"

{context_summary}

Extract the following information:

1. Intent: What is the user asking for?
   - "cve_search": User wants to find CVEs/vulnerabilities (e.g., "what vulnerabilities", "find CVEs", "security issues")
   - "risk_assessment": User wants risk analysis (e.g., "risk assessment", "how risky", "severity")
   - "mitigation": User wants mitigation strategies (e.g., "how to fix", "mitigation plan", "patch")
   - "followup": User is asking follow-up about previous results (e.g., "tell me more", "explain", "what about")
   - "tech_stack": User wants to see detected technologies
   - "general": General query that should default to CVE search

2. Technologies: Extract ALL technology/product names mentioned (e.g., ["Apple", "Apple products", "Apache Kafka", "Docker"]).
   Return as a JSON array. If no specific technology mentioned, return empty array [].

3. Is Reference: Does the query reference previous results? (true/false)
   - true if query contains: "above", "these", "those", "mentioned", "previous", "earlier", "found", "discovered"
   - true if query doesn't mention specific tech but asks about "my stack", "the stack", "these technologies"
   - false if query mentions a new technology not in context

4. Context Type: Which context should be used?
   - "image": If query references image-detected tech stack (e.g., "my stack", "these technologies", "above")
   - "text": If query is about a new search or text-based context
   - "auto": Let system decide (use when unclear)

5. Search Query: Clean query for CVE search - extract technology names and vulnerability-related terms.
   Remove conversational parts like "I am going to use", "what kind of", "can I encounter".
   Example: "I am going to use apple products, what kind of vulnerabilities can i encounter?" -> "Apple products vulnerabilities"

Return ONLY valid JSON in this exact format (no markdown, no code blocks):
{{
    "intent": "cve_search",
    "technologies": ["Apple products"],
    "is_reference": false,
    "context_type": "text",
    "search_query": "Apple products vulnerabilities"
}}"""

            # Use LLM with timeout and error handling
            from langchain_core.messages import HumanMessage
            
            response = self.llm.invoke([HumanMessage(content=prompt)])
            
            # Extract JSON from response
            response_text = response.content.strip()
            
            # Remove markdown code blocks if present
            if response_text.startswith("```json"):
                response_text = response_text[7:]
            if response_text.startswith("```"):
                response_text = response_text[3:]
            if response_text.endswith("```"):
                response_text = response_text[:-3]
            response_text = response_text.strip()
            
            # Parse JSON
            result = json.loads(response_text)
            
            # Validate result structure
            required_keys = ['intent', 'technologies', 'is_reference', 'context_type', 'search_query']
            if not all(key in result for key in required_keys):
                raise ValueError(f"Missing required keys in LLM response: {result}")
            
            # Validate intent
            valid_intents = ['cve_search', 'risk_assessment', 'mitigation', 'followup', 'tech_stack', 'general']
            if result['intent'] not in valid_intents:
                result['intent'] = 'general'  # Default fallback
            
            # Validate context_type
            valid_contexts = ['image', 'text', 'auto']
            if result['context_type'] not in valid_contexts:
                result['context_type'] = 'auto'
            
            # Ensure technologies is a list
            if not isinstance(result['technologies'], list):
                result['technologies'] = []
            
            # Ensure search_query is a string
            if not isinstance(result['search_query'], str):
                result['search_query'] = ' '.join(result.get('technologies', [])) + ' vulnerabilities'
            
            return result
            
        except json.JSONDecodeError as e:
            print(f"[WARNING] LLM returned invalid JSON, using fallback: {e}")
            return self._parse_query_fallback(user_input)
        except Exception as e:
            print(f"[WARNING] LLM parsing failed, using fallback: {e}")
            return self._parse_query_fallback(user_input)
    
    def _parse_query_fallback(self, user_input):
        """
        Fallback keyword-based query parsing when LLM fails.
        Uses existing keyword-based detection logic.
        
        Args:
            user_input: User's query
            
        Returns:
            dict with same structure as _parse_query_with_llm()
        """
        if not user_input:
            return {
                'intent': 'general',
                'technologies': [],
                'is_reference': False,
                'context_type': 'text',
                'search_query': ''
            }
        
        input_lower = user_input.lower()
        
        # Detect intent using keyword matching (call existing method)
        intent = self._detect_intent_keyword_fallback(user_input, self.conversation_context)
        
        # Detect if reference query
        reference_words = ['above', 'below', 'mentioned', 'these', 'those', 'this', 'that',
                          'previous', 'returned', 'detected', 'shown', 'listed', 'found',
                          'earlier', 'discovered', 'my stack', 'the stack']
        is_reference = any(ref_word in input_lower for ref_word in reference_words)
        
        # Detect context type (call existing method)
        context_type = self._detect_context_type_keyword_fallback(user_input)
        
        # Extract technologies (simple word-based extraction)
        technologies = []
        
        # Check if query mentions technologies from image context
        if self.image_context.get('tech_stack'):
            image_tech_stack_lower = [t.lower() for t in self.image_context['tech_stack']]
            for tech in self.image_context['tech_stack']:
                if tech.lower() in input_lower:
                    technologies.append(tech)
        
        # Extract potential technology names from query
        # Remove common words
        words = input_lower.split()
        filtered_words = [w for w in words if w not in [
            'cve', 'cves', 'vulnerability', 'vulnerabilities', 'for', 'in', 'about',
            'the', 'my', 'all', 'give', 'me', 'show', 'tell', 'what', 'are', 'is',
            'going', 'to', 'use', 'can', 'i', 'encounter', 'kind', 'of', 'what',
            'am', 'will', 'be', 'using', 'products', 'product'
        ]]
        
        # Try to find technology names (capitalize first letter)
        if filtered_words:
            # Take first 2-3 words as potential tech name
            potential_tech = ' '.join(filtered_words[:3]).title()
            if potential_tech and potential_tech not in technologies:
                technologies.append(potential_tech)
        
        # Generate search query
        if technologies:
            search_query = f"{' '.join(technologies)} vulnerabilities"
        else:
            # Use original query, cleaned up
            search_query = ' '.join(filtered_words) + ' vulnerabilities' if filtered_words else user_input
        
        return {
            'intent': intent,
            'technologies': technologies,
            'is_reference': is_reference,
            'context_type': context_type,
            'search_query': search_query
        }
    
    def _route_to_risk_assessment(self, user_input):
        """
        Route to Risk Assessment Agent - PURE ROUTING.
        Uses appropriate context (image or text) based on query.
        Now processes each technology separately when CVEs come from tech stack search.
        """
        # Detect which context to use
        context_type = self._detect_context_type(user_input)
        active_context = self._get_active_context(context_type)
        
        # Extract technology from user input
        input_lower = user_input.lower()
        requested_tech = None
        
        # Reference words that indicate user is referring to previous search results
        reference_words = [
            'above', 'below', 'mentioned', 'these', 'those', 'this', 'that',
            'previous', 'returned', 'detected', 'shown', 'listed', 'found',
            'the above', 'above mentioned', 'mentioned above', 'shown above'
        ]
        
        # Check if query contains reference words (user is referring to previous results)
        is_reference_query = any(ref_word in input_lower for ref_word in reference_words)
        
        # Check if query mentions a specific tech
        if context_type == "image":
            # Check image context tech stack
            tech_stack = active_context.get('tech_stack')
            if tech_stack:
                for tech in tech_stack:
                    if tech.lower() in input_lower:
                        requested_tech = tech
                        break
        else:
            # TEXT CONTEXT: Prioritize context over extraction
            last_search_term = active_context.get('last_search_term')
            
            # If query contains reference words, use last_search_term from context
            if is_reference_query and last_search_term:
                requested_tech = last_search_term
            # Check if last_search_term is explicitly mentioned in query
            elif last_search_term and last_search_term.lower() in input_lower:
                requested_tech = last_search_term
            
            # Only try to extract from query if no tech found yet AND not a reference query
            if not requested_tech and not is_reference_query:
                # Expanded filter list to exclude reference words and conversational phrases
                filter_words = [
                    'the', 'my', 'all', 'these', 'those', 'this', 'that',
                    'above', 'below', 'mentioned', 'previous', 'returned', 'detected',
                    'give', 'me', 'show', 'tell', 'can', 'you', 'do', 'the',
                    'cves', 'cve', 'vulnerabilities', 'vulnerability', 'risk', 'assessment',
                    'for', 'in', 'about', 'related', 'to', 'of', 'on', 'with',
                    'analysis', 'analyze', 'assess', 'evaluate'
                ]
                
                # Improved regex patterns - more specific to avoid matching conversational phrases
                tech_patterns = [
                    # Pattern 1: "for [tech]" or "in [tech]" or "about [tech]" - but NOT if followed by reference words
                    r'(?:for|in|about|related to)\s+([a-z]+(?:\s+[a-z]+)?)(?:\s+(?:cves?|vulnerabilities?|risk|assessment))?(?!\s+(?:above|below|mentioned|these|those))',
                    # Pattern 2: "[tech] cves" or "[tech] vulnerabilities" - but NOT if preceded by reference words
                    r'(?<!above\s)(?<!below\s)(?<!mentioned\s)(?<!these\s)(?<!those\s)([a-z]+(?:\s+[a-z]+)?)\s+(?:cves?|vulnerabilities?)(?:\s+(?:above|below|mentioned))?',
                    # Pattern 3: "[tech] risk" or "[tech] assessment" - but NOT if preceded by conversational phrases
                    r'(?<!give\s)(?<!me\s)(?<!do\s)(?<!the\s)([a-z]+(?:\s+[a-z]+)?)\s+(?:risk|assessment)',
                ]
                
                for pattern in tech_patterns:
                    match = re.search(pattern, input_lower)
                    if match:
                        potential_tech = match.group(1).strip()
                        # Check if it's a valid tech name (not a filter word and meaningful)
                        if (potential_tech and len(potential_tech) > 2 and
                            potential_tech not in filter_words and
                            not any(ref in potential_tech for ref in reference_words)):
                            requested_tech = potential_tech.title()
                            break
            
            # Final fallback: if still no tech found but we have last_search_term, use it
            if not requested_tech and last_search_term:
                requested_tech = last_search_term
        
        # Get CVEs from appropriate context
        stored_cves = active_context.get('cves')
        last_output = active_context.get('last_output')
        
        # Check if last output is from tech stack CVE search (has 'results' dict)
        if active_context.get('last_agent') == 'CVESearchAgent' and last_output:
            if isinstance(last_output, dict) and 'results' in last_output:
                # Tech stack search result - process each technology separately
                results_dict = last_output.get('results', {})
                
                # If specific tech requested, only process that one
                if requested_tech and requested_tech in results_dict:
                    tech_result = results_dict[requested_tech]
                    tech_cves = tech_result.get('cves')
                    if tech_cves is not None and len(tech_cves) > 0:
                        # Assess ALL CVEs for this single tech
                        risk_result = self.risk_assessment_agent.assess_risk(
                            cves_df=tech_cves,
                            tech_stack=[requested_tech],
                            use_llm=False,
                            silent=True
                        )
                        
                        reports_by_tech = {
                            requested_tech: {
                                "ranked_cves": risk_result.get('ranked_cves'),
                                "summary": risk_result.get('summary', ''),
                                "assessments": risk_result.get('assessments', [])
                            }
                        }
                    else:
                        reports_by_tech = {}
                else:
                    # Process ALL technologies separately - use ALL CVEs for each
                    reports_by_tech = {}
                    
                    for tech, tech_result in results_dict.items():
                        tech_cves = tech_result.get('cves')
                        if tech_cves is not None and len(tech_cves) > 0:
                            # Assess ALL CVEs for this technology (no limit)
                            risk_result = self.risk_assessment_agent.assess_risk(
                                cves_df=tech_cves,
                                tech_stack=[tech],
                                use_llm=False,
                                silent=True
                            )
                            
                            reports_by_tech[tech] = {
                                "ranked_cves": risk_result.get('ranked_cves'),
                                "summary": risk_result.get('summary', ''),
                                "assessments": risk_result.get('assessments', [])
                            }
                
                # Generate clean table format with proper tech names
                if reports_by_tech:
                    clean_format = self.risk_assessment_agent._generate_clean_table_format(reports_by_tech)
                    
                    result = {
                        "answer": clean_format.get('conclusion', ''),
                        "assessments": [],
                        "ranked_cves": None,  # Combined ranking not needed when per-tech
                        "summary": clean_format.get('conclusion', ''),
                        "by_tech": reports_by_tech,
                        "detailed_explanation": clean_format.get('conclusion', ''),
                        "reports_by_tech": reports_by_tech,
                        "clean_table": clean_format.get('table', ''),
                        "most_least_severe": clean_format.get('most_least_severe', {})
                    }
                else:
                    # No CVEs found
                    result = {
                        "answer": "No CVEs found for risk assessment.",
                        "assessments": [],
                        "ranked_cves": None,
                        "summary": "No CVEs found.",
                        "by_tech": {},
                        "reports_by_tech": {},
                        "clean_table": "No CVEs found.",
                        "most_least_severe": {}
                    }
            elif isinstance(last_output, dict) and 'cves' in last_output:
                # Regular search result (not tech stack)
                stored_cves = last_output.get('cves')
                if stored_cves is not None and len(stored_cves) > 0:
                    # Determine tech stack - PRIORITIZE last_search_term for reference queries
                    if requested_tech:
                        assessment_tech_stack = [requested_tech]
                    elif is_reference_query and active_context.get('last_search_term'):
                        # For reference queries, use last_search_term even if not explicitly mentioned
                        assessment_tech_stack = [active_context.get('last_search_term')]
                    else:
                        assessment_tech_stack = [active_context.get('last_search_term')] if active_context.get('last_search_term') else None
                    
                    # Assess ALL CVEs (no limit)
                    risk_result = self.risk_assessment_agent.assess_risk(
                        cves_df=stored_cves,
                        tech_stack=assessment_tech_stack,
                        use_llm=False,
                        silent=True
                    )
                    
                    # Format result
                    if assessment_tech_stack:
                        reports_by_tech = {}
                        for tech in assessment_tech_stack:
                            reports_by_tech[tech] = {
                                "ranked_cves": risk_result.get('ranked_cves'),
                                "summary": risk_result.get('summary', ''),
                                "assessments": risk_result.get('assessments', [])
                            }
                    else:
                        reports_by_tech = {"General": {
                            "ranked_cves": risk_result.get('ranked_cves'),
                            "summary": risk_result.get('summary', ''),
                            "assessments": risk_result.get('assessments', [])
                        }}
                    
                    clean_format = self.risk_assessment_agent._generate_clean_table_format(reports_by_tech)
                    
                    result = {
                        "answer": clean_format.get('conclusion', risk_result.get('summary', '')),
                        "assessments": risk_result.get('assessments', []),
                        "ranked_cves": risk_result.get('ranked_cves', []),
                        "summary": clean_format.get('conclusion', risk_result.get('summary', '')),
                        "by_tech": reports_by_tech,
                        "detailed_explanation": clean_format.get('conclusion', ''),
                        "reports_by_tech": reports_by_tech,
                        "clean_table": clean_format.get('table', ''),
                        "most_least_severe": clean_format.get('most_least_severe', {})
                    }
                else:
                    # No stored CVEs - search database
                    result = self.risk_assessment_agent.query_risk(
                        question=user_input,
                        tech_stack=active_context.get('tech_stack') if context_type == "image" else None,
                        silent=True
                    )
        elif stored_cves is not None and len(stored_cves) > 0:
            # Use stored CVEs from context (legacy path)
            # Determine tech stack for assessment
            if context_type == "image":
                assessment_tech_stack = active_context.get('tech_stack')
            else:
                # For text context, prioritize last_search_term for reference queries
                if is_reference_query and active_context.get('last_search_term'):
                    assessment_tech_stack = [active_context.get('last_search_term')]
                elif requested_tech:
                    assessment_tech_stack = [requested_tech]
                else:
                    assessment_tech_stack = [active_context.get('last_search_term')] if active_context.get('last_search_term') else None
            
            risk_result = self.risk_assessment_agent.assess_risk(
                cves_df=stored_cves,
                tech_stack=assessment_tech_stack,
                use_llm=False,
                silent=True
            )
            
            # Format result
            if assessment_tech_stack:
                reports_by_tech = {}
                for tech in assessment_tech_stack:
                    reports_by_tech[tech] = {
                        "ranked_cves": risk_result.get('ranked_cves', []),
                        "summary": risk_result.get('summary', ''),
                        "assessments": risk_result.get('assessments', [])
                    }
            else:
                reports_by_tech = {"General": {
                    "ranked_cves": risk_result.get('ranked_cves', []),
                    "summary": risk_result.get('summary', ''),
                    "assessments": risk_result.get('assessments', [])
                }}
            
            clean_format = self.risk_assessment_agent._generate_clean_table_format(reports_by_tech)
            
            result = {
                "answer": clean_format.get('conclusion', risk_result.get('summary', '')),
                "assessments": risk_result.get('assessments', []),
                "ranked_cves": risk_result.get('ranked_cves', []),
                "summary": clean_format.get('conclusion', risk_result.get('summary', '')),
                "by_tech": reports_by_tech,
                "detailed_explanation": clean_format.get('conclusion', ''),
                "reports_by_tech": reports_by_tech,
                "clean_table": clean_format.get('table', ''),
                "most_least_severe": clean_format.get('most_least_severe', {})
            }
        else:
            # No stored CVEs - search database
            result = self.risk_assessment_agent.query_risk(
                question=user_input,
                tech_stack=active_context.get('tech_stack') if context_type == "image" else None,
                silent=True
            )
        
        # Update context
        self._update_context(context_type, {
            'risk_assessment': result,
            'last_agent': 'RiskAssessmentAgent',
            'last_output': result
        })
        
        # Format output - SIMPLIFIED: Only table and most/least severe
        output = "\n" + "="*80 + "\n"
        output += "RISK ASSESSMENT\n"
        output += "="*80 + "\n\n"
        
        # Show table
        if result.get('clean_table'):
            output += "TECH STACK RISK METRICS:\n"
            output += "-"*80 + "\n"
            output += result['clean_table'] + "\n"
        
        # Add most/least severe if available - FORMAT WITH BULLET POINTS
        if result.get('most_least_severe'):
            output += "\n" + "="*80 + "\n"
            output += "MOST & LEAST SEVERE CVEs BY TECH STACK:\n"
            output += "="*80 + "\n"
            for tech, data in result['most_least_severe'].items():
                output += f"\n**{tech.upper()}:**\n"
                if 'most_severe' in data and data['most_severe']:
                    cve_id = data['most_severe'].get('cve_id', 'N/A')
                    risk_score = data['most_severe'].get('risk_score', 0)
                    risk_level = data['most_severe'].get('risk_level', 'N/A')
                    title = data['most_severe'].get('title', 'N/A')
                    output += f"- **Most Severe:** {cve_id} - Risk Score: {risk_score:.2f}/10 ({risk_level})\n"
                    if title and title != 'N/A':
                        output += f"  - Title: {title}\n"
                if 'least_severe' in data and data['least_severe']:
                    cve_id = data['least_severe'].get('cve_id', 'N/A')
                    risk_score = data['least_severe'].get('risk_score', 0)
                    risk_level = data['least_severe'].get('risk_level', 'N/A')
                    title = data['least_severe'].get('title', 'N/A')
                    output += f"- **Least Severe:** {cve_id} - Risk Score: {risk_score:.2f}/10 ({risk_level})\n"
                    if title and title != 'N/A':
                        output += f"  - Title: {title}\n"
        
        output += "\n" + "="*80 + "\n"
        
        return {
            "status": "success",
            "agent": "RiskAssessmentAgent",
            "result": result,
            "output": output
        }
    
    def _extract_clean_tech_stack_from_output(self, tech_result):
        """
        Extract clean tech stack list from "TECHNOLOGIES:" section in the output.
        Improved to handle error responses.
        
        Args:
            tech_result: Result dict from TechStackDetectionAgent
        
        Returns:
            List of clean technology names
        """
        # Try to get from details or raw_response
        response_text = tech_result.get('details') or tech_result.get('raw_response', '')
        
        if not response_text:
            # Fallback to tech_stack if available
            return tech_result.get('tech_stack', [])
        
        # FIRST: Check if "TECHNOLOGIES:" exists - if it does, it's not a complete error
        has_technologies_section = "TECHNOLOGIES:" in response_text.upper()
        
        # Check if this is an error response (but only if no TECHNOLOGIES section)
        response_lower = response_text.lower()
        error_indicators = [
            'unable to identify', 'unable to analyze', 'cannot identify',
            'cannot analyze', 'error', 'failed', "i'm unable"
        ]
        
        # Only treat as error if it has error indicators AND no technologies section
        if not has_technologies_section and any(indicator in response_lower for indicator in error_indicators):
            # This is an error response with no technologies, return empty list
            return []
        
        # Look for "TECHNOLOGIES:" section
        if has_technologies_section:
            lines = response_text.split('\n')
            for i, line in enumerate(lines):
                line_upper = line.upper()
                if "TECHNOLOGIES:" in line_upper:
                    # Get the technologies line
                    tech_line = line.split("TECHNOLOGIES:")[-1].strip()
                    
                    # If current line is just "TECHNOLOGIES:", check next line
                    if not tech_line and i + 1 < len(lines):
                        tech_line = lines[i + 1].strip()
                    
                    # If still empty, try splitting by colon
                    if not tech_line:
                        parts = line.split(':', 1)
                        if len(parts) > 1:
                            tech_line = parts[1].strip()
                    
                    if tech_line:
                        # Split by comma and clean each technology
                        techs = [t.strip() for t in tech_line.split(',')]
                        clean_techs = []
                        for tech in techs:
                            # Clean up: remove trailing punctuation, parentheses content
                            tech = tech.strip('.,;:')
                            # Remove content in parentheses (e.g., "3rd Party Services (Google, MixPanel)" -> "3rd Party Services")
                            if '(' in tech:
                                tech = tech.split('(')[0].strip()
                            # Remove content in brackets
                            if '[' in tech:
                                tech = tech.split('[')[0].strip()
                            
                            # Skip error messages or invalid tech names
                            if tech and len(tech) > 1 and tech.lower() not in ["i'm", "i", "unable", "error"]:
                                clean_techs.append(tech)
                        
                        # Remove duplicates while preserving order
                        if clean_techs:
                            seen = set()
                            unique_techs = []
                            for tech in clean_techs:
                                tech_lower = tech.lower()
                                if tech_lower not in seen:
                                    seen.add(tech_lower)
                                    unique_techs.append(tech)
                            return unique_techs
                    break
        
        # Fallback: return tech_stack from result if TECHNOLOGIES: not found
        return tech_result.get('tech_stack', [])
    
    def _format_tech_stack_cve_output(self, result):
        """
        Format CVE search results for tech stack to display all CVEs.
        Returns markdown-formatted output with numbered technologies and bullet points for CVEs.
        
        Args:
            result: Result dict from search_cves_for_tech_stack with structure:
                {
                    "results": {
                        "tech1": {"cves": DataFrame, "answer": str},
                        "tech2": {"cves": DataFrame, "answer": str}
                    },
                    "summary": str,
                    "total_cves": int
                }
        
        Returns:
            Formatted markdown string displaying all CVEs for each technology
        """
        if not result or 'results' not in result:
            return result.get('summary', 'No results found.')
        
        output_parts = []
        
        results_dict = result.get('results', {})
        total_cves = result.get('total_cves', 0)
        
        tech_count = 0
        for tech, tech_result in results_dict.items():
            tech_count += 1
            cves_df = tech_result.get('cves')
            
            if cves_df is not None and len(cves_df) > 0:
                # Format as markdown: numbered technology with bullet points for CVEs
                output_parts.append(f"\n**{tech_count}. Technology: {tech}**\n")
                
                # Extract CVE IDs and title information
                if 'cve_id' in cves_df.columns:
                    for idx, row in cves_df.iterrows():
                        cve_id = row['cve_id']
                        
                        # Get CVE title instead of vendor/technology
                        title_info = None
                        
                        # Check for title column
                        if 'title' in cves_df.columns and pd.notna(row.get('title')):
                            title_info = str(row['title']).strip()
                        
                        # Format as markdown bullet point: CVE-ID - Title
                        if title_info:
                            output_parts.append(f"- {cve_id} - {title_info}")
                        else:
                            output_parts.append(f"- {cve_id}")
                else:
                    output_parts.append("- CVE IDs: Not available")
                
                output_parts.append("")  # Empty line between technologies
            else:
                output_parts.append(f"\n**{tech_count}. Technology: {tech}**\n")
                output_parts.append("- No CVEs found for this technology.")
                output_parts.append("")
        
        return "\n".join(output_parts)
    
    def _route_to_mitigation(self, user_input):
        """
        Route to Risk Mitigation Agent - PURE ROUTING.
        Extracts CVE-IDs from input or context and passes to agent, then stores result.
        Now supports natural language queries like "all critical CVEs", "most severe", etc.
        CHECKS if stored CVEs match requested technology before using them.
        AUTOMATICALLY searches for CVEs if tech stack mentioned but stored CVEs don't match.
        """
        input_lower = user_input.lower()
        
        # IMPORTANT: Check for severity keywords FIRST (before tech extraction)
        # These should NOT be treated as tech stack names
        severity_keywords = ['critical', 'high', 'medium', 'low', 'severe', 'highest', 'most severe']
        is_severity_query = any(keyword in input_lower for keyword in severity_keywords)
        
        # Common phrases to ignore when extracting tech stack
        # ADD: reference phrases like "above", "these", "those", "this", "that" should not be treated as tech names
        ignore_phrases = ['give me', 'show me', 'tell me', 'get me', 'provide', 'i want', 'i need', 
                         'above', 'these', 'those', 'this', 'that', 'the above', 'above cves', 
                         'above vulnerabilities', 'these cves', 'those cves', 'this cves']
        
        # Check if user is referring to "above" or similar reference phrases
        is_reference_query = any(phrase in input_lower for phrase in [
            'above', 'these', 'those', 'this', 'that', 'the above', 'above cves',
            'above vulnerabilities', 'these cves', 'those cves', 'this cves'
        ])
        
        # STEP 1: Extract requested technology from user input FIRST
        requested_tech = None
        
        # Check if tech_stack exists in context and user mentions a tech from it
        tech_stack = self.conversation_context.get('tech_stack')
        if tech_stack:
            for tech in tech_stack:
                tech_lower = tech.lower()
                if tech_lower in input_lower:
                    requested_tech = tech
                    break
        
        # If no tech found in context, try to extract from user input directly
        # BUT skip if the word is a severity keyword, common phrase, or reference phrase
        if not requested_tech and not is_reference_query:
            tech_patterns = [
                r'mitigation\s+(?:for|of|on)\s+([a-z]+(?:\s+[a-z]+)?)',  # "mitigation for Jenkins" - check this FIRST
                r'for\s+([a-z]+(?:\s+[a-z]+)?)\s+(?:cves?|vulnerabilities?)',  # "for Jenkins CVEs"
                r'related\s+to\s+([a-z]+(?:\s+[a-z]+)?)',  # "related to Jenkins"
                r'in\s+([a-z]+(?:\s+[a-z]+)?)',  # "in Jenkins"
                r'([a-z]+(?:\s+[a-z]+)?)\s+(?:cves?|vulnerabilities?|mitigation)',  # "Jenkins CVEs", "Apache Airflow mitigation"
            ]
            
            for pattern in tech_patterns:
                match = re.search(pattern, input_lower)
                if match:
                    tech = match.group(1).strip()
                    # Remove common trailing words
                    tech = re.sub(r'\s+(cves?|vulnerabilities?|issues?|mitigation)$', '', tech)
                    # IMPORTANT: Don't treat severity keywords, common phrases, reference phrases, or short words as tech stack
                    tech_lower = tech.lower()
                    if (tech and len(tech) > 2 and 
                        tech_lower not in severity_keywords and 
                        tech_lower not in ignore_phrases and
                        not tech_lower.startswith('give') and
                        not tech_lower.startswith('show') and
                        not tech_lower.startswith('tell')):
                        requested_tech = tech
                        break
        
        # STEP 2: Extract CVE-IDs from input first
        cve_ids = self._extract_cve_ids_from_context(user_input, self.conversation_context)
        
        # STEP 3: If no CVE-IDs in input, extract from context BUT CHECK IF THEY MATCH REQUESTED TECH
        stored_cves_match_request = False
        
        if not cve_ids:
            # Check risk assessment context for CVEs
            if self.conversation_context.get('risk_assessment'):
                risk_assessment = self.conversation_context['risk_assessment']
                
                # NEW: If user says "above cves" or similar, extract most severe CVEs from most_least_severe
                if is_reference_query and risk_assessment.get('most_least_severe'):
                    most_least_severe = risk_assessment.get('most_least_severe', {})
                    cve_ids = []
                    
                    # Extract most severe CVE from each technology
                    for tech, data in most_least_severe.items():
                        if 'most_severe' in data and data['most_severe']:
                            cve_id = data['most_severe'].get('cve_id')
                            if cve_id:
                                cve_ids.append(cve_id)
                    
                    if cve_ids:
                        stored_cves_match_request = True
                        print(f"\n[INFO] Extracted {len(cve_ids)} most severe CVEs from risk assessment for mitigation.")
                
                # If still no CVEs, try ranked_cves DataFrame
                if not cve_ids:
                    risk_df = risk_assessment.get('ranked_cves')
                    
                    if risk_df is not None and len(risk_df) > 0:
                        # PRIORITY: If severity is mentioned, prioritize severity-based extraction
                        if is_severity_query:
                            # Extract CVEs by severity first (regardless of tech)
                            if any(phrase in input_lower for phrase in ['all critical', 'all the critical', 'critical cves', 'critical vulnerabilities', 'critical']):
                                critical_cves = risk_df[risk_df['risk_level'] == 'Critical']
                                if len(critical_cves) > 0:
                                    cve_ids = critical_cves['cve_id'].tolist()
                                    stored_cves_match_request = True
                                else:
                                    # Fallback to High if no Critical
                                    high_cves = risk_df[risk_df['risk_level'] == 'High']
                                    if len(high_cves) > 0:
                                        cve_ids = high_cves['cve_id'].tolist()
                                        stored_cves_match_request = True
                            elif any(phrase in input_lower for phrase in ['all high', 'all the high', 'high cves', 'high severity', 'high']):
                                high_cves = risk_df[risk_df['risk_level'] == 'High']
                                if len(high_cves) > 0:
                                    cve_ids = high_cves['cve_id'].tolist()
                                    stored_cves_match_request = True
                            elif any(phrase in input_lower for phrase in ['all medium', 'all the medium', 'medium cves', 'medium']):
                                medium_cves = risk_df[risk_df['risk_level'] == 'Medium']
                                if len(medium_cves) > 0:
                                    cve_ids = medium_cves['cve_id'].tolist()
                                    stored_cves_match_request = True
                            elif any(phrase in input_lower for phrase in ['highest', 'most severe', 'top', 'first', 'worst', 'top 1']):
                                top_critical = risk_df[risk_df['risk_level'].isin(['Critical', 'High'])].head(1)
                                if len(top_critical) > 0:
                                    cve_ids = [top_critical.iloc[0]['cve_id']]
                                    stored_cves_match_request = True
                                else:
                                    cve_ids = [risk_df.iloc[0]['cve_id']]
                                    stored_cves_match_request = True
                            elif any(phrase in input_lower for phrase in ['top', 'first']) and any(word in input_lower for word in ['5', '10', '15', '20']):
                                numbers = re.findall(r'\d+', input_lower)
                                if numbers:
                                    top_n = int(numbers[0])
                                    cve_ids = risk_df.head(top_n)['cve_id'].tolist()
                                    stored_cves_match_request = True
                            elif any(phrase in input_lower for phrase in ['all', 'every', 'each']):
                                all_cves = risk_df.head(20)
                                cve_ids = all_cves['cve_id'].tolist()
                                stored_cves_match_request = True
                        
                        # If severity query didn't find CVEs, or no severity mentioned, try tech-based filtering
                        if not cve_ids and requested_tech:
                            # Check if any CVE in risk_df mentions the requested tech
                            requested_tech_lower = requested_tech.lower()
                            matching_cves = None
                            
                            for col in ['product_name', 'vendor_name', 'title']:
                                if col in risk_df.columns:
                                    mask = risk_df[col].astype(str).str.lower().str.contains(requested_tech_lower, na=False)
                                    if mask.any():
                                        matching_cves = risk_df[mask]
                                        break
                            
                            if matching_cves is not None and len(matching_cves) > 0:
                                # Stored CVEs match requested tech - use them
                                stored_cves_match_request = True
                                # Parse user query to determine which CVEs to select
                                if any(phrase in input_lower for phrase in ['all critical', 'all the critical', 'critical cves', 'critical vulnerabilities', 'critical']):
                                    critical_cves = matching_cves[matching_cves['risk_level'] == 'Critical']
                                    if len(critical_cves) > 0:
                                        cve_ids = critical_cves['cve_id'].tolist()
                                    else:
                                        high_cves = matching_cves[matching_cves['risk_level'] == 'High']
                                        if len(high_cves) > 0:
                                            cve_ids = high_cves['cve_id'].tolist()
                                elif any(phrase in input_lower for phrase in ['all high', 'all the high', 'high cves', 'high severity', 'high']):
                                    high_cves = matching_cves[matching_cves['risk_level'] == 'High']
                                    if len(high_cves) > 0:
                                        cve_ids = high_cves['cve_id'].tolist()
                                elif any(phrase in input_lower for phrase in ['all medium', 'all the medium', 'medium cves', 'medium']):
                                    medium_cves = matching_cves[matching_cves['risk_level'] == 'Medium']
                                    if len(medium_cves) > 0:
                                        cve_ids = medium_cves['cve_id'].tolist()
                                elif any(phrase in input_lower for phrase in ['highest', 'most severe', 'top', 'first', 'worst', 'top 1']):
                                    top_critical = matching_cves[matching_cves['risk_level'].isin(['Critical', 'High'])].head(1)
                                    if len(top_critical) > 0:
                                        cve_ids = [top_critical.iloc[0]['cve_id']]
                                    else:
                                        cve_ids = [matching_cves.iloc[0]['cve_id']]
                                elif any(phrase in input_lower for phrase in ['top', 'first']) and any(word in input_lower for word in ['5', '10', '15', '20']):
                                    numbers = re.findall(r'\d+', input_lower)
                                    if numbers:
                                        top_n = int(numbers[0])
                                        cve_ids = matching_cves.head(top_n)['cve_id'].tolist()
                                elif any(phrase in input_lower for phrase in ['all', 'every', 'each']):
                                    all_cves = matching_cves.head(20)
                                    cve_ids = all_cves['cve_id'].tolist()
                                else:
                                    # Default: get top 5 most severe CVEs
                                    top_cves = matching_cves.head(5)
                                    cve_ids = top_cves['cve_id'].tolist()
                        
                        # If still no CVEs and no severity/tech filtering worked, use default (top 5)
                        # BUT: If it's a reference query like "above cves", use most severe from each tech
                        if not cve_ids and not is_severity_query and not requested_tech:
                            if is_reference_query and risk_assessment.get('most_least_severe'):
                                # Already handled above, but fallback here too
                                most_least_severe = risk_assessment.get('most_least_severe', {})
                                cve_ids = []
                                for tech, data in most_least_severe.items():
                                    if 'most_severe' in data and data['most_severe']:
                                        cve_id = data['most_severe'].get('cve_id')
                                        if cve_id:
                                            cve_ids.append(cve_id)
                                if cve_ids:
                                    stored_cves_match_request = True
                            else:
                                stored_cves_match_request = True
                                top_cves = risk_df.head(5)
                                cve_ids = top_cves['cve_id'].tolist()

            # If still no CVEs, check stored CVEs from CVE search (only if no risk assessment or severity query)
            if not cve_ids and not is_severity_query:
                last_output = self.conversation_context.get('last_output')
                if last_output and isinstance(last_output, dict):
                    # Check if it's a tech stack CVE search result
                    if 'results' in last_output:
                        results_dict = last_output.get('results', {})
                        
                        # If user requested specific tech, check if we have CVEs for it
                        if requested_tech:
                            # Normalize requested tech for comparison
                            requested_tech_lower = requested_tech.lower()
                            # Check if requested tech is in stored results
                            for stored_tech, tech_result in results_dict.items():
                                if stored_tech.lower() == requested_tech_lower:
                                    tech_cves = tech_result.get('cves')
                                    if tech_cves is not None and len(tech_cves) > 0:
                                        stored_cves_match_request = True
                                        # Get top 5 by default
                                        cve_ids = tech_cves.head(5)['cve_id'].tolist()
                                        break
                        else:
                            # No specific tech requested - use all stored CVEs
                            stored_cves_match_request = True
                            # Extract all CVEs from tech stack results
                            all_cves = []
                            for tech_result in results_dict.values():
                                tech_cves = tech_result.get('cves')
                                if tech_cves is not None and len(tech_cves) > 0:
                                    all_cves.append(tech_cves)
                            
                            if all_cves:
                                combined_cves = pd.concat(all_cves, ignore_index=True)
                                cve_ids = combined_cves.head(5)['cve_id'].tolist()
                    
                    # Or if it's a regular search result
                    elif 'cves' in last_output:
                        stored_cves_df = last_output.get('cves')
                        if stored_cves_df is not None and len(stored_cves_df) > 0:
                            # If user requested specific tech, check if stored CVEs match
                            if requested_tech:
                                requested_tech_lower = requested_tech.lower()
                                matching_cves = None
                                
                                for col in ['product_name', 'vendor_name', 'title']:
                                    if col in stored_cves_df.columns:
                                        mask = stored_cves_df[col].astype(str).str.lower().str.contains(requested_tech_lower, na=False)
                                        if mask.any():
                                            matching_cves = stored_cves_df[mask]
                                            stored_cves_match_request = True
                                            break
                                
                                if matching_cves is not None and len(matching_cves) > 0:
                                    cve_ids = matching_cves.head(5)['cve_id'].tolist()
                            else:
                                # No specific tech requested - use stored CVEs
                                stored_cves_match_request = True
                                cve_ids = stored_cves_df.head(5)['cve_id'].tolist()
        
        # STEP 4: If no CVEs found OR stored CVEs don't match requested tech, search automatically
        # BUT only if requested_tech is actually a tech stack (not a severity keyword or common phrase)
        if not cve_ids or (requested_tech and not stored_cves_match_request and 
                          requested_tech.lower() not in severity_keywords and 
                          requested_tech.lower() not in ignore_phrases):
            if requested_tech and requested_tech.lower() not in severity_keywords and requested_tech.lower() not in ignore_phrases:
                print(f"\n[INFO] No matching CVEs found in context for '{requested_tech}'. Automatically searching for CVEs...\n")
                
                # Automatically trigger CVE search for the tech stack
                cve_search_result = self._route_to_cve_search(f"what are the CVEs for {requested_tech}")
                
                # Extract CVEs from the search result
                if cve_search_result.get('status') == 'success':
                    search_output = cve_search_result.get('result', {})
                    
                    # Check if it's a tech stack search result
                    if 'results' in search_output:
                        results_dict = search_output.get('results', {})
                        if requested_tech in results_dict:
                            tech_result = results_dict[requested_tech]
                            tech_cves = tech_result.get('cves')
                            if tech_cves is not None and len(tech_cves) > 0:
                                # Get top 5 CVEs by default (or parse user query for specific count)
                                if any(phrase in input_lower for phrase in ['all', 'every', 'each']):
                                    cve_ids = tech_cves['cve_id'].tolist()[:20]  # Limit to 20
                                elif any(word in input_lower for word in ['5', '10', '15', '20']):
                                    numbers = re.findall(r'\d+', input_lower)
                                    if numbers:
                                        top_n = int(numbers[0])
                                        cve_ids = tech_cves.head(top_n)['cve_id'].tolist()
                                else:
                                    # Default: top 5 most severe
                                    cve_ids = tech_cves.head(5)['cve_id'].tolist()
                    
                    # Or if it's a regular search result
                    elif 'cves' in search_output:
                        stored_cves_df = search_output.get('cves')
                        if stored_cves_df is not None and len(stored_cves_df) > 0:
                            cve_ids = stored_cves_df.head(5)['cve_id'].tolist()
        
        # Prepare input for agent
        if cve_ids:
            cve_input = ', '.join(cve_ids)
            # Pass the original user query as the question parameter
            result = self.risk_mitigation_agent.generate_mitigation_roadmap(
                cve_id_or_text=cve_input,
                question=user_input  # Pass full query as question for context
            )
        else:
            # No CVEs found - provide helpful error message
            error_message = "No CVEs found to generate mitigation plan. "
            if is_severity_query:
                error_message += "Please ensure you have run a risk assessment first, or specify CVEs by ID."
            elif requested_tech and requested_tech.lower() not in ignore_phrases:
                error_message += f"Could not find CVEs for '{requested_tech}'. Please check the technology name or run a CVE search first."
            else:
                error_message += "Please provide CVE-IDs, run a risk assessment, or search for CVEs first."
                
            return {
                "status": "error",
                "agent": "RiskMitigationAgent",
                "result": {"error": error_message},
                "output": error_message
            }
        
        # Store agent output in context
        self.conversation_context['last_agent'] = 'RiskMitigationAgent'
        self.conversation_context['last_output'] = result
        
        # Add to conversation history
        self.conversation_context['conversation_history'].append({
            "input": user_input,
            "agent": "RiskMitigationAgent",
            "output": result
        })
        
        # Format output
        output = result.get('formatted_output', result.get('roadmap', 'Mitigation roadmap generated.'))
        
        # If there's an error in the result, include it in output
        if result.get('error'):
            output = result.get('error', output)
        
        # Store mitigation in context
        self.conversation_context['mitigation'] = result
        
        # Generate report if risk assessment is also available
        pdf_path = self._generate_report_if_ready()
        
        response_dict = {
            "status": "success" if not result.get('error') else "error",
            "agent": "RiskMitigationAgent",
            "result": result,
            "output": output
        }
        
        # Add report path if generated
        if pdf_path:
            response_dict['report_pdf_path'] = pdf_path
        
        return response_dict
    
    def _handle_followup(self, user_input):
        """
        Handle follow-up questions using conversation context.
        Now allows CVE search at any point, regardless of last agent.
        
        Args:
            user_input: User follow-up query
        
        Returns:
            dict with agent results
        """
        last_agent = self.conversation_context.get('last_agent')
        last_output = self.conversation_context.get('last_output')
        
        if not last_agent or not last_output:
            # No previous context - treat as new query
            return self._route_with_context(user_input)
        
        # Route based on last agent and follow-up intent
        input_lower = user_input.lower()
        
        # PRIORITY: Check if user is asking about CVEs (regardless of last agent)
        # This allows CVE search at any point in the conversation
        cve_search_indicators = [
            'cve', 'cves', 'vulnerability', 'vulnerabilities', 
            'about the cves', 'about these cves', 'about those cves',
            'the cves', 'these cves', 'those cves', 'all the cves',
            'know about', 'tell me about', 'show me', 'list'
        ]
        
        if any(indicator in input_lower for indicator in cve_search_indicators):
            # User wants CVE search - route to CVE search agent
            # It will automatically use tech stack from memory if available
            return self._route_to_cve_search(user_input)
        
        # Check for risk assessment requests
        if any(keyword in input_lower for keyword in ['risk', 'assess', 'assessment', 'severity', 'risk level']):
            return self._route_to_risk_assessment(user_input)
        
        # Check for mitigation requests
        if any(keyword in input_lower for keyword in ['mitigation', 'mitigate', 'fix', 'patch', 'roadmap', 'steps', 'solution']):
            return self._route_to_mitigation(user_input)
        
        # Route based on last agent (fallback)
        if last_agent == "RiskAssessmentAgent":
            # Follow-up to risk assessment
            # More details about risk assessment - use risk assessment agent's follow-up capability
            result = self.risk_assessment_agent.query_risk(user_input, silent=True)
            
            # Update context
            self.conversation_context['last_agent'] = 'RiskAssessmentAgent'
            self.conversation_context['last_output'] = result
            
            # Format output
            output = "\n" + "="*80 + "\n"
            output += "RISK ASSESSMENT (FOLLOW-UP)\n"
            output += "="*80 + "\n"
            output += result.get('answer', result.get('summary', 'No additional information available.'))
            output += "\n" + "="*80 + "\n"
            
            return {
                "status": "success",
                "agent": "RiskAssessmentAgent",
                "result": result,
                "output": output
            }
        
        elif last_agent == "CVESearchAgent":
            # Follow-up to CVE search
            # More CVEs or details - use CVE search agent
            return self._route_to_cve_search(user_input)
        
        elif last_agent == "RiskMitigationAgent":
            # Follow-up to mitigation
            # Check if asking about CVEs from mitigation plan
            if any(indicator in input_lower for indicator in cve_search_indicators):
                return self._route_to_cve_search(user_input)
            # Otherwise, route to mitigation for more details
            return self._route_to_mitigation(user_input)
        
        elif last_agent == "TechStackDetectionAgent":
            # Follow-up to tech stack detection
            # User probably wants CVEs for detected tech stack
            if any(keyword in input_lower for keyword in ['cve', 'vulnerability', 'vulnerabilities', 'find', 'search', 'show']):
                return self._route_to_cve_search(user_input)
            else:
                # Return tech stack info again
                tech_result = self.conversation_context.get('last_output')
                output = "\n" + "="*80 + "\n"
                output += "DETECTED TECHNOLOGIES:\n"
                output += "="*80 + "\n\n"
                tech_stack = tech_result.get('tech_stack', [])
                output += f"{', '.join(tech_stack)}\n"
                output += f"Total: {len(tech_stack)} technologies\n"
                output += "\n" + "="*80 + "\n"
                
                return {
                    "status": "success",
                    "agent": "TechStackDetectionAgent",
                    "result": tech_result,
                    "output": output
                }
        
        # Default: treat as new query
        return self._route_with_context(user_input)
    
    def _extract_cve_ids_from_context(self, user_input, conversation_context):
        """
        Extract CVE-IDs from user input using regex.
        
        Args:
            user_input: User text query
            conversation_context: Conversation context (for future use)
        
        Returns:
            List of CVE-IDs found (e.g., ['CVE-2024-50603', 'CVE-2024-57937'])
        """
        if not user_input:
            return []
        
        # Pattern to match CVE-ID: CVE-YYYY-NNNNN (4 digits, dash, 4-7 digits)
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        matches = re.findall(cve_pattern, user_input.upper())
        
        # Remove duplicates and return list
        return list(set(matches))
    
    def _detect_intent(self, user_input, conversation_context):
        """
        Detect user intent from input query.
        Uses LLM-based parsing with keyword fallback.
        
        Args:
            user_input: User text query
            conversation_context: Conversation context for context-aware detection
        
        Returns:
            str: One of "cve_search", "risk_assessment", "mitigation", "followup", "tech_stack", "general"
        """
        if not user_input:
            return "general"
        
        try:
            # Try LLM-based parsing first
            parsed = self._parse_query_with_llm(user_input)
            intent = parsed.get('intent', 'general')
            
            # Validate intent
            valid_intents = ['cve_search', 'risk_assessment', 'mitigation', 'followup', 'tech_stack', 'general']
            if intent in valid_intents:
                return intent
            else:
                # Fallback to keyword-based
                return self._detect_intent_keyword_fallback(user_input, conversation_context)
        except Exception as e:
            print(f"[WARNING] Intent detection failed, using keyword fallback: {e}")
            return self._detect_intent_keyword_fallback(user_input, conversation_context)
    
    def _detect_intent_keyword_fallback(self, user_input, conversation_context):
        """
        Original keyword-based intent detection (fallback).
        This is the EXACT current implementation.
        """
        if not user_input:
            return "general"
        
        input_lower = user_input.lower()
        
        # Check for explicit CVE-ID queries first (highest priority)
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        if re.search(cve_pattern, user_input, re.IGNORECASE):
            # If CVE-ID is mentioned with mitigation/risk keywords, prioritize those
            if any(keyword in input_lower for keyword in ['mitigation', 'mitigate', 'fix', 'patch', 'roadmap', 'solution', 'steps']):
                return "mitigation"
            elif any(keyword in input_lower for keyword in ['risk', 'assess', 'assessment', 'severity', 'risk level', 'analyze']):
                return "risk_assessment"
            else:
                return "cve_search"
        
        # Check for mitigation intent (with priority over risk assessment when both present)
        mitigation_keywords = ['mitigation', 'mitigate', 'fix', 'patch', 'roadmap', 'solution', 'steps', 'remediation', 'how to fix', 'how to patch']
        mitigation_phrases = [
            'give me mitigation', 'show me mitigation', 'mitigation plan', 'mitigation strategy',
            'how to mitigate', 'how to fix', 'how to patch', 'fix for', 'patch for'
        ]
        
        has_mitigation = any(keyword in input_lower for keyword in mitigation_keywords) or \
                        any(phrase in input_lower for phrase in mitigation_phrases)
        
        # Check for risk assessment intent
        risk_keywords = ['risk', 'assess', 'assessment', 'severity', 'risk level', 'risk score', 'analyze risk', 'risk analysis']
        risk_phrases = [
            'risk assessment', 'assess risk', 'risk analysis', 'what is the risk',
            'risk level', 'risk score', 'how risky', 'severity'
        ]
        
        has_risk = any(keyword in input_lower for keyword in risk_keywords) or \
                  any(phrase in input_lower for phrase in risk_phrases)
        
        # Priority: mitigation > risk assessment (when both present)
        if has_mitigation:
            return "mitigation"
        elif has_risk:
            return "risk_assessment"
        
        # Check for CVE search intent
        cve_keywords = ['cve', 'cves', 'vulnerability', 'vulnerabilities', 'find cve', 'search cve', 'list cve', 'show cve']
        cve_phrases = [
            'what are the cves', 'list all cves', 'find vulnerabilities', 'search for cve',
            'cve for', 'cves for', 'vulnerabilities for', 'cve related to', 'cves related to'
        ]
        
        has_cve_search = any(keyword in input_lower for keyword in cve_keywords) or \
                        any(phrase in input_lower for phrase in cve_phrases)
        
        if has_cve_search:
            return "cve_search"
        
        # Check for tech stack intent
        tech_stack_keywords = ['tech stack', 'technologies', 'technology stack', 'what technologies', 'detected technologies']
        if any(keyword in input_lower for keyword in tech_stack_keywords):
            return "tech_stack"
        
        # Check for follow-up (if there's previous context)
        last_agent = conversation_context.get('last_agent')
        if last_agent:
            # Check for follow-up indicators
            followup_indicators = ['more', 'details', 'explain', 'tell me more', 'what about', 'how about', 'also']
            if any(indicator in input_lower for indicator in followup_indicators):
                return "followup"
        
        # Default: general query (will route to CVE search)
        return "general"
    
    def _log_memory_usage(self, user_input, intent):
        """
        Log what memory/context is being used for routing decision.
        
        Args:
            user_input: User's input query
            intent: Detected intent
        """
        print(f"\n[INFO] Memory State:")
        print(f"  - Last Agent: {self.conversation_context.get('last_agent', 'None')}")
        
        tech_stack = self.conversation_context.get('tech_stack')
        if tech_stack:
            print(f"  - Tech Stack in Memory: {', '.join(tech_stack) if isinstance(tech_stack, list) else tech_stack}")
        else:
            print(f"  - Tech Stack in Memory: None")
        
        has_cves = self.conversation_context.get('cves') is not None
        cves_count = 0
        if has_cves:
            cves_data = self.conversation_context.get('cves')
            if isinstance(cves_data, pd.DataFrame):
                cves_count = len(cves_data)
            elif isinstance(cves_data, dict) and 'results' in cves_data:
                # Count CVEs from tech stack results
                total = 0
                for tech_result in cves_data.get('results', {}).values():
                    if isinstance(tech_result, dict) and 'cves' in tech_result:
                        tech_cves = tech_result.get('cves')
                        if tech_cves is not None:
                            total += len(tech_cves) if hasattr(tech_cves, '__len__') else 0
                cves_count = total
        print(f"  - CVEs in Memory: {'Yes (' + str(cves_count) + ' CVEs)' if has_cves else 'No'}")
        
        has_risk = self.conversation_context.get('risk_assessment') is not None
        print(f"  - Risk Assessment in Memory: {'Yes' if has_risk else 'No'}")
        print(f"  - Conversation History Length: {len(self.conversation_context.get('conversation_history', []))}")
        print(f"  - Detected Intent: {intent}")
        print(f"  - Using Context: {'Yes' if self.conversation_context.get('last_agent') else 'No'}\n")
    
    def _route_with_context(self, user_input):
        """
        Route text query to appropriate agent based on intent and context.
        
        Args:
            user_input: User text query
        
        Returns:
            dict with agent results
        """
        # Detect intent with context
        intent = self._detect_intent(user_input, self.conversation_context)
        
        # Log memory usage before routing
        self._log_memory_usage(user_input, intent)
        
        print(f"[INFO] Routing to appropriate agent...")
        print("="*80)
        
        try:
            # Route based on intent
            if intent == "cve_search":
                print("[INFO] Routing to CVESearchAgent")
                return self._route_to_cve_search(user_input)
            
            elif intent == "risk_assessment":
                print("[INFO] Routing to RiskAssessmentAgent")
                return self._route_to_risk_assessment(user_input)
            
            elif intent == "mitigation":
                print("[INFO] Routing to RiskMitigationAgent")
                return self._route_to_mitigation(user_input)
            
            elif intent == "followup":
                print("[INFO] Handling follow-up question")
                return self._handle_followup(user_input)
            
            elif intent == "tech_stack":
                # Tech stack detection for text queries (usually should be image)
                if self.conversation_context.get('tech_stack'):
                    # User asking about tech stack, show what we have
                    tech_stack = self.conversation_context['tech_stack']
                    output = "\n" + "="*80 + "\n"
                    output += "DETECTED TECHNOLOGIES:\n"
                    output += "="*80 + "\n\n"
                    output += f"Technologies: {', '.join(tech_stack)}\n"
                    output += f"Total: {len(tech_stack)} technologies\n"
                    output += "\n[INFO] To detect technologies from an image, please provide an image path."
                    output += "\n" + "="*80 + "\n"
                    
                    return {
                        "status": "success",
                        "agent": "TechStackDetectionAgent",
                        "result": {"tech_stack": tech_stack},
                        "output": output
                    }
                else:
                    # No tech stack in context, inform user
                    output = "\n" + "="*80 + "\n"
                    output += "TECH STACK DETECTION\n"
                    output += "="*80 + "\n\n"
                    output += "[INFO] To detect technologies from an architecture image, please provide an image path.\n"
                    output += "Example: 'network_architecture.png'\n"
                    output += "\n" + "="*80 + "\n"
                    
                    return {
                        "status": "info",
                        "agent": "PlannerAgent",
                        "output": output
                    }
            
            elif intent == "general":
                # General query - default to CVE search
                print("[INFO] General query - routing to CVESearchAgent")
                return self._route_to_cve_search(user_input)
            
            else:
                # Fallback - should not reach here
                print(f"[WARNING] Unknown intent: {intent}, defaulting to CVE search")
                return self._route_to_cve_search(user_input)
        
        except Exception as e:
            print(f"\n[ERROR] Processing failed: {e}")
            import traceback
            traceback.print_exc()
            
            return {
                "status": "error",
                "message": str(e),
                "output": f"Error: {e}"
            }
    
    def clear_history(self):
        """Clear all agent histories and conversation context."""
        self.tech_stack_agent.clear_history()
        self.cve_search_agent.clear_history()
        self.risk_assessment_agent.clear_history()
        self.risk_mitigation_agent.clear_history()
        self.report_generation_agent.clear_history() # Clear report generation agent history
        
        # Reset conversation context
        self.conversation_context = {
            "tech_stack": None,
            "cves": None,
            "risk_assessment": None,
            "mitigation": None,
            "last_agent": None,
            "last_output": None,
            "conversation_history": []
        }

    def _generate_report_if_ready(self):
        """
        Check if risk assessment OR mitigation is complete, then generate PDF.
        Works with either one or both.
        
        Returns:
            str or None: Path to PDF if generated, None otherwise
        """
        risk_assessment = self.conversation_context.get('risk_assessment')
        mitigation = self.conversation_context.get('mitigation')
        
        # Generate if at least one is available
        if risk_assessment or mitigation:
            try:
                print(f"\n[INFO] Generating PDF report...")
                print(f"[INFO] Risk assessment available: {risk_assessment is not None}")
                print(f"[INFO] Mitigation available: {mitigation is not None}")
                
                pdf_path = self.report_generation_agent.generate_report_from_context(
                    self.conversation_context
                )
                
                # Store PDF path in context
                self.conversation_context['report_pdf_path'] = pdf_path
                print(f"[INFO] PDF report generated successfully: {pdf_path}")
                return pdf_path
            except Exception as e:
                import traceback
                print(f"[WARNING] Failed to generate report: {e}")
                traceback.print_exc()
                return None
        else:
            print(f"\n[INFO] Report not ready - Risk assessment: {risk_assessment is not None}, Mitigation: {mitigation is not None}")
        
        return None

    def _detect_input_type(self, user_input):
        """
        Auto-detect if input is an image path or text query.
        
        Args:
            user_input: User input string
        
        Returns:
            "image" or "text"
        """
        # Check if input is a file path (image)
        if os.path.exists(user_input):
            # Check if it's an image file
            image_extensions = ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp']
            file_ext = os.path.splitext(user_input.lower())[1]
            if file_ext in image_extensions:
                return "image"
        
        return "text"
    
    def process(self, user_input):
        """
        Main method: Process user input and route to appropriate agent.
        Maintains conversation context and supports step-by-step interactions.
        
        Args:
            user_input: User input (text query or image path)
        
        Returns:
            dict with agent results
        """
        if not user_input or not user_input.strip():
            return {
                "status": "error",
                "message": "No input provided.",
                "output": None
            }
        
        # Detect input type
        input_type = self._detect_input_type(user_input)
        
        if input_type == "image":
            # Image input - route to Tech Stack Detection Agent
            return self._route_to_tech_stack_detection(user_input)
        else:
            # Text query - detect intent and route with context
            return self._route_with_context(user_input)


if __name__ == "__main__":
    # Test the Planner Agent
    print("="*80)
    print("PLANNER AGENT - CVE Analysis System")
    print("="*80)
    print("\nEnter a query or image path to analyze.")
    print("Examples:")
    print("  - 'network_architecture.png' (detects tech stack)")
    print("  - 'Give me all CVEs for these technologies' (searches CVEs)")
    print("  - 'Do risk analysis' (assesses risk)")
    print("  - 'Give me mitigation for the highest risk CVE' (generates mitigation)")
    print("\nType 'quit', 'exit', or 'q' to stop.")
    print("Type 'clear' or 'reset' to clear all histories.")
    print("-"*80)
    
    # Initialize planner
    planner = PlannerAgent(provider="openai")
    
    while True:
        try:
            # Get user input
            user_input = input("\nYou: ").strip()
            
            if user_input.lower() in ['quit', 'exit', 'q']:
                print("\nGoodbye!")
                break
            
            if user_input.lower() in ['clear', 'reset']:
                planner.clear_history()
                print("\n[INFO] All conversation histories cleared.\n")
                continue
            
            if not user_input:
                continue
            
            # Process input
            result = planner.process(user_input)
            
            # Display output
            if result['status'] == 'success':
                print(result['output'])
            else:
                print(f"\n[ERROR] {result.get('message', 'Unknown error')}")
            
            print("\n" + "-"*80)
            
        except KeyboardInterrupt:
            print("\n\n[INFO] Interrupted by user")
            break
        except Exception as e:
            print(f"\n[ERROR] An error occurred: {e}")
            import traceback
            traceback.print_exc()
            print("\n" + "-"*80)