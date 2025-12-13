import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import os
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage
import pandas as pd
import numpy as np
from contextlib import redirect_stdout
import io

load_dotenv()

class RiskAssessmentAgent:
    """
    Agent that assesses risk for CVEs.
    Calculates overall risk scores, explains metrics, and ranks CVEs by priority.
    Supports multiple tech stacks and maintains conversation memory.
    """
    
    def __init__(self, provider="openai", model="gpt-4o-mini", temperature=0.3):
        """
        Initialize the Risk Assessment Agent.
        
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
        self.previous_assessments = None  # Store previous risk assessments
    
    def _calculate_risk_score(self, cvss_score, epss_score):
        """
        Calculate overall risk score using formula:
        Overall Risk Score = (CVSS × 0.60) + (EPSS × 10 × 0.40)
        
        Args:
            cvss_score: CVSS score (0-10) or None
            epss_score: EPSS score (0-1) or None
        
        Returns:
            Overall risk score (0-10) or None if both scores are missing
        """
        # Handle missing values
        if pd.isna(cvss_score) or cvss_score is None:
            cvss_score = 0
        if pd.isna(epss_score) or epss_score is None:
            epss_score = 0
        
        # Calculate overall risk score
        overall_score = (cvss_score * 0.60) + (epss_score * 10 * 0.40)
        
        return round(overall_score, 2)
    
    def _explain_epss(self, epss_score):
        """
        Explain EPSS score in human-readable format.
        
        Args:
            epss_score: EPSS score (0-1)
        
        Returns:
            Explanation string
        """
        if pd.isna(epss_score) or epss_score is None:
            return "EPSS Score: Not available - Exploitability probability unknown"
        
        percentage = round(epss_score * 100, 1)
        
        if epss_score >= 0.7:
            level = "Very High"
        elif epss_score >= 0.5:
            level = "High"
        elif epss_score >= 0.3:
            level = "Medium"
        elif epss_score >= 0.1:
            level = "Low"
        else:
            level = "Very Low"
        
        return f"EPSS Score: {epss_score:.3f} → {percentage}% chance of exploitation in next 30 days ({level} probability)"
    
    def _explain_cvss(self, cvss_score, cvss_severity=None):
        """
        Explain CVSS score in human-readable format.
        
        Args:
            cvss_score: CVSS score (0-10)
            cvss_severity: CVSS severity (Critical/High/Medium/Low) or None
        
        Returns:
            Explanation string
        """
        if pd.isna(cvss_score) or cvss_score is None:
            return "CVSS Score: Not available - Severity unknown"
        
        if cvss_severity:
            severity = cvss_severity
        else:
            # Determine severity from score
            if cvss_score >= 9.0:
                severity = "Critical"
            elif cvss_score >= 7.0:
                severity = "High"
            elif cvss_score >= 4.0:
                severity = "Medium"
            else:
                severity = "Low"
        
        # Add impact description
        if cvss_score >= 9.0:
            impact = "Can cause complete system compromise, data breach, or service disruption"
        elif cvss_score >= 7.0:
            impact = "Can cause significant damage, data exposure, or service interruption"
        elif cvss_score >= 4.0:
            impact = "Can cause moderate damage or limited data exposure"
        else:
            impact = "Causes minimal damage or limited impact"
        
        return f"CVSS Score: {cvss_score:.1f} ({severity}) → {impact}"
    
    def _calculate_relevance_score(self, cve_row, tech_stack):
        """
        Calculate relevance score based on how well CVE matches tech stack.
        
        Args:
            cve_row: Single CVE row from DataFrame
            tech_stack: List of technologies (e.g., ["Jenkins", "Python"])
        
        Returns:
            Relevance score (0-1)
        """
        if not tech_stack or len(tech_stack) == 0:
            return 0.5  # Neutral if no tech stack provided
        
        # Check if CVE mentions any technology in tech stack
        cve_text = ""
        for col in ['title', 'description', 'product', 'vendor', 'combined_text']:
            if col in cve_row.index and pd.notna(cve_row[col]):
                cve_text += str(cve_row[col]).lower() + " "
        
        # Count matches
        matches = 0
        for tech in tech_stack:
            if tech.lower() in cve_text:
                matches += 1
        
        # Calculate relevance (0-1)
        relevance = min(matches / len(tech_stack), 1.0)
        return relevance
    
    def _assess_single_cve(self, cve_row, tech_stack=None):
        """
        Assess risk for a single CVE.
        
        Args:
            cve_row: Single CVE row from DataFrame
            tech_stack: List of technologies (optional)
        
        Returns:
            dict with risk assessment details
        """
        cve_id = cve_row.get('cve_id', 'Unknown')
        cvss_score = cve_row.get('cvss_score')
        epss_score = cve_row.get('epss_score')
        cvss_severity = cve_row.get('cvss_severity')
        
        # Calculate overall risk score
        overall_risk = self._calculate_risk_score(cvss_score, epss_score)
        
        # Get explanations
        epss_explanation = self._explain_epss(epss_score)
        cvss_explanation = self._explain_cvss(cvss_score, cvss_severity)
        
        # Calculate relevance if tech stack provided
        relevance = None
        if tech_stack:
            relevance = self._calculate_relevance_score(cve_row, tech_stack)
        
        # Determine risk level
        if overall_risk >= 9.0:
            risk_level = "Critical"
            priority = 1
        elif overall_risk >= 7.0:
            risk_level = "High"
            priority = 2
        elif overall_risk >= 4.0:
            risk_level = "Medium"
            priority = 3
        else:
            risk_level = "Low"
            priority = 4
        
        # Build calculation breakdown
        cvss_val = cvss_score if pd.notna(cvss_score) else 0
        epss_val = epss_score if pd.notna(epss_score) else 0
        cvss_contribution = cvss_val * 0.60
        epss_contribution = epss_val * 10 * 0.40
        
        calculation = f"Overall Risk Score = (CVSS × 0.60) + (EPSS × 10 × 0.40)\n"
        if pd.notna(cvss_score):
            calculation += f"                  = ({cvss_score:.1f} × 0.60) + "
        else:
            calculation += f"                  = (N/A × 0.60) + "
        
        if pd.notna(epss_score):
            calculation += f"({epss_score:.3f} × 10 × 0.40)\n"
        else:
            calculation += f"(N/A × 10 × 0.40)\n"
        
        calculation += f"                  = {cvss_contribution:.2f} + {epss_contribution:.2f}\n"
        calculation += f"                  = {overall_risk:.2f}/10"
        
        return {
            'cve_id': cve_id,
            'overall_risk_score': overall_risk,
            'risk_level': risk_level,
            'priority': priority,
            'cvss_score': cvss_score,
            'epss_score': epss_score,
            'cvss_severity': cvss_severity,
            'epss_explanation': epss_explanation,
            'cvss_explanation': cvss_explanation,
            'calculation': calculation,
            'relevance': relevance,
            'title': cve_row.get('title', 'N/A')
        }
    
    def assess_risk(self, cves_df, tech_stack=None, use_llm=True, silent=False):
        """
        Assess risk for CVEs and rank them by priority.
        
        Args:
            cves_df: DataFrame with CVEs (must have 'cve_id', 'cvss_score', 'epss_score')
            tech_stack: List of technologies (optional, e.g., ["Jenkins", "Python"])
            use_llm: Whether to use LLM for detailed explanations (default: True)
            silent: If True, suppress all print output (default: False)
        
        Returns:
            dict with 'assessments' (list), 'ranked_cves' (DataFrame), 'summary' (str), 'by_tech' (dict)
        """
        if cves_df is None or len(cves_df) == 0:
            return {
                "assessments": [],
                "ranked_cves": None,
                "summary": "No CVEs provided for risk assessment.",
                "by_tech": {},
                "overall_ranking": None
            }
        
        if not silent:
            print(f"\nAssessing risk for {len(cves_df)} CVEs...")
            print("="*80)
        
        # Assess each CVE
        assessments = []
        for idx, row in cves_df.iterrows():
            assessment = self._assess_single_cve(row, tech_stack)
            assessments.append(assessment)
        
        # Create DataFrame with assessments
        assessment_df = pd.DataFrame(assessments)
        
        # Sort by overall risk score (descending)
        assessment_df = assessment_df.sort_values('overall_risk_score', ascending=False)
        assessment_df['rank'] = range(1, len(assessment_df) + 1)
        
        # Group by tech stack if provided
        by_tech = {}
        if tech_stack:
            # Try to match CVEs to technologies
            for tech in tech_stack:
                tech_cves = []
                for assessment in assessments:
                    # Check if CVE is related to this tech
                    cve_row = cves_df[cves_df['cve_id'] == assessment['cve_id']].iloc[0]
                    relevance = self._calculate_relevance_score(cve_row, [tech])
                    if relevance > 0.3:  # Threshold for relevance
                        tech_cves.append(assessment)
                
                if tech_cves:
                    # Sort by risk score
                    tech_cves_sorted = sorted(tech_cves, key=lambda x: x['overall_risk_score'], reverse=True)
                    by_tech[tech] = tech_cves_sorted
        
        # Generate summary
        summary = self._generate_summary(assessment_df, by_tech, tech_stack)
        
        # Use LLM for detailed explanation if requested
        detailed_explanation = None
        if use_llm:
            detailed_explanation = self._generate_llm_explanation(assessment_df, tech_stack)
        
        # Store in conversation history
        self.conversation_history.append({
            "input": {
                "cve_count": len(cves_df),
                "tech_stack": tech_stack
            },
            "output": {
                "assessments": assessments,
                "ranked_cves": assessment_df,
                "summary": summary
            }
        })
        
        # Store previous assessments for follow-ups
        self.previous_assessments = assessment_df
        
        return {
            "assessments": assessments,
            "ranked_cves": assessment_df,
            "summary": summary,
            "by_tech": by_tech,
            "overall_ranking": assessment_df,
            "detailed_explanation": detailed_explanation
        }
    
    def _generate_summary(self, assessment_df, by_tech, tech_stack):
        """
        Generate summary of risk assessment.
        
        Args:
            assessment_df: DataFrame with risk assessments
            by_tech: Dict with assessments grouped by technology
            tech_stack: List of technologies
        
        Returns:
            Summary string
        """
        if len(assessment_df) == 0:
            return "No CVEs to assess."
        
        # Count by risk level
        risk_counts = assessment_df['risk_level'].value_counts().to_dict()
        
        summary_parts = []
        summary_parts.append(f"Total CVEs Assessed: {len(assessment_df)}")
        summary_parts.append(f"\nRisk Distribution:")
        for level in ["Critical", "High", "Medium", "Low"]:
            count = risk_counts.get(level, 0)
            if count > 0:
                summary_parts.append(f"  - {level}: {count}")
        
        # Top 3 highest risk
        top_3 = assessment_df.head(3)
        summary_parts.append(f"\nTop 3 Highest Risk CVEs:")
        for idx, row in top_3.iterrows():
            summary_parts.append(f"  {row['rank']}. {row['cve_id']} - Risk Score: {row['overall_risk_score']:.2f}/10 ({row['risk_level']})")
        
        # By tech stack if provided
        if by_tech:
            summary_parts.append(f"\nBy Technology:")
            for tech, tech_cves in by_tech.items():
                tech_counts = {}
                for cve in tech_cves:
                    level = cve['risk_level']
                    tech_counts[level] = tech_counts.get(level, 0) + 1
                
                tech_summary = ", ".join([f"{count} {level}" for level, count in tech_counts.items()])
                summary_parts.append(f"  - {tech}: {len(tech_cves)} CVEs ({tech_summary})")
        
        return "\n".join(summary_parts)
    
    def _generate_llm_explanation(self, assessment_df, tech_stack):
        """
        Use LLM to generate detailed risk assessment explanation.
        
        Args:
            assessment_df: DataFrame with risk assessments
            tech_stack: List of technologies
        
        Returns:
            Detailed explanation string
        """
        try:
            # Prepare context
            top_5 = assessment_df.head(5)
            
            context = "Risk Assessment Results:\n\n"
            for idx, row in top_5.iterrows():
                context += f"CVE {row['rank']}: {row['cve_id']}\n"
                context += f"  - {row['cvss_explanation']}\n"
                context += f"  - {row['epss_explanation']}\n"
                context += f"  - Overall Risk: {row['overall_risk_score']:.2f}/10 ({row['risk_level']})\n"
                context += f"  - {row['calculation']}\n\n"
            
            if tech_stack:
                context += f"\nDetected Tech Stack: {', '.join(tech_stack)}\n"
            
            prompt = f"""Based on the following risk assessment results, provide a concise summary and recommendations.

{context}

Please provide:
1. Overall risk summary (2-3 sentences)
2. Key concerns (top 3-5 CVEs that need immediate attention)
3. Recommendations (what should be prioritized and why)

Keep it concise and actionable."""
            
            messages = [
                SystemMessage(content="You are a cybersecurity risk assessment expert. Provide clear, actionable risk analysis."),
                HumanMessage(content=prompt)
            ]
            
            # Add conversation history
            if self.conversation_history:
                for item in self.conversation_history[-3:]:  # Last 3 conversations
                    if "summary" in item.get("output", {}):
                        messages.append(HumanMessage(content=f"Previous assessment: {item['output']['summary']}"))
            
            response = self.llm.invoke(messages)
            return response.content
            
        except Exception as e:
            print(f"[WARNING] LLM explanation failed: {e}")
            return None
    
    def _generate_clean_table_format(self, reports_by_tech):
        """
        Generate clean table format with tech stacks, risk metrics, most/least severe CVEs, and conclusion.
        
        Args:
            reports_by_tech: Dict mapping tech names to their reports
        
        Returns:
            dict with 'table' (str), 'most_least_severe' (dict), 'conclusion' (str)
        """
        if not reports_by_tech:
            return {
                "table": "No tech stacks found.",
                "most_least_severe": {},
                "conclusion": "No data available."
            }
        
        # Build table data
        table_data = []
        most_least_by_tech = {}
        
        for tech, report in reports_by_tech.items():
            ranked_cves = report.get('ranked_cves')
            if ranked_cves is None or len(ranked_cves) == 0:
                continue
            
            # Calculate metrics
            total_cves = len(ranked_cves)
            avg_risk = ranked_cves['overall_risk_score'].mean()
            
            # Count by risk level
            risk_counts = ranked_cves['risk_level'].value_counts().to_dict()
            critical = risk_counts.get('Critical', 0)
            high = risk_counts.get('High', 0)
            medium = risk_counts.get('Medium', 0)
            low = risk_counts.get('Low', 0)
            
            # Most severe (highest risk score)
            most_severe = ranked_cves.iloc[0]
            # Least severe (lowest risk score)
            least_severe = ranked_cves.iloc[-1]
            
            table_data.append({
                'Tech Stack': tech.title(),
                'Overall Risk Score': f"{avg_risk:.2f}/10",
                'Critical': critical,
                'High': high,
                'Medium': medium,
                'Low': low,
                'Total CVEs': total_cves
            })
            
            most_least_by_tech[tech] = {
                'most_severe': {
                    'cve_id': most_severe['cve_id'],
                    'risk_score': most_severe['overall_risk_score'],
                    'risk_level': most_severe['risk_level'],
                    'title': most_severe.get('title', 'N/A')
                },
                'least_severe': {
                    'cve_id': least_severe['cve_id'],
                    'risk_score': least_severe['overall_risk_score'],
                    'risk_level': least_severe['risk_level'],
                    'title': least_severe.get('title', 'N/A')
                }
            }
        
        # Create table - DYNAMIC MARKDOWN TABLE FORMAT (handles any number of rows)
        if not table_data:
            table_str = "No data available."
        else:
            # Create markdown table dynamically
            table_lines = []
            
            # Define headers with double spacing
            headers = ['Tech Stack', 'Overall Risk Score', 'Critical', 'High', 'Medium', 'Low', 'Total CVEs']
            
            # Header row with double spaces between columns
            table_lines.append("| " + "  |  ".join(headers) + " |")
            
            # Separator row (required for markdown tables)
            table_lines.append("| " + "  |  ".join(["---" for _ in headers]) + " |")
            
            # Data rows - dynamically handles any number of rows
            for row in table_data:
                row_values = [
                    str(row.get('Tech Stack', '')),
                    str(row.get('Overall Risk Score', '')),
                    str(row.get('Critical', '')),
                    str(row.get('High', '')),
                    str(row.get('Medium', '')),
                    str(row.get('Low', '')),
                    str(row.get('Total CVEs', ''))
                ]
                # Double spaces between columns
                table_lines.append("| " + "  |  ".join(row_values) + " |")
            
            table_str = "\n".join(table_lines)
        
        # Generate conclusion using LLM
        conclusion = self._generate_conclusion(reports_by_tech, most_least_by_tech)
        
        return {
            "table": table_str,
            "most_least_severe": most_least_by_tech,
            "conclusion": conclusion
        }
    
    def _generate_conclusion(self, reports_by_tech, most_least_by_tech):
        """
        Generate conclusion using LLM based on risk assessment data.
        
        Args:
            reports_by_tech: Dict mapping tech names to their reports
            most_least_by_tech: Dict with most/least severe CVEs per tech
        
        Returns:
            Conclusion string
        """
        try:
            context = "Risk Assessment Summary:\n\n"
            
            for tech, report in reports_by_tech.items():
                ranked_cves = report.get('ranked_cves')
                if ranked_cves is None or len(ranked_cves) == 0:
                    continue
                
                avg_risk = ranked_cves['overall_risk_score'].mean()
                risk_counts = ranked_cves['risk_level'].value_counts().to_dict()
                
                context += f"{tech.upper()}:\n"
                context += f"  - Average Risk Score: {avg_risk:.2f}/10\n"
                context += f"  - Risk Distribution: {dict(risk_counts)}\n"
                
                if tech in most_least_by_tech:
                    most = most_least_by_tech[tech]['most_severe']
                    least = most_least_by_tech[tech]['least_severe']
                    context += f"  - Most Severe: {most['cve_id']} (Risk: {most['risk_score']:.2f}/10, {most['risk_level']})\n"
                    context += f"  - Least Severe: {least['cve_id']} (Risk: {least['risk_score']:.2f}/10, {least['risk_level']})\n"
                context += "\n"
            
            prompt = f"""Based on the following risk assessment data, provide a concise conclusion (2-3 paragraphs) that:
1. Summarizes the overall risk landscape across all technologies
2. Highlights key findings (which tech has highest risk, most critical vulnerabilities)
3. Provides actionable recommendations

{context}

Keep it concise and actionable. Do NOT show formulas or calculations."""

            messages = [
                SystemMessage(content="You are a cybersecurity risk assessment expert. Provide clear, actionable conclusions."),
                HumanMessage(content=prompt)
            ]
            
            response = self.llm.invoke(messages)
            return response.content
            
        except Exception as e:
            return f"Risk assessment completed for {len(reports_by_tech)} technologies. Review the table above for details."
    
    def _generate_direct_answer(self, question, reports_by_tech, most_least_by_tech):
        """
        Generate a direct, conversational answer to the user's question.
        Like ChatGPT - just answer what's asked, nothing extra.
        
        Args:
            question: User's original question
            reports_by_tech: Dict mapping tech names to their reports
            most_least_by_tech: Dict with most/least severe CVEs per tech
        
        Returns:
            Direct answer string
        """
        try:
            context = "Risk Assessment Data:\n\n"
            
            for tech, report in reports_by_tech.items():
                ranked_cves = report.get('ranked_cves')
                if ranked_cves is None or len(ranked_cves) == 0:
                    continue
                
                avg_risk = ranked_cves['overall_risk_score'].mean()
                risk_counts = ranked_cves['risk_level'].value_counts().to_dict()
                
                context += f"{tech.upper()}:\n"
                context += f"  - Average Risk Score: {avg_risk:.2f}/10\n"
                context += f"  - Risk Distribution: {dict(risk_counts)}\n"
                context += f"  - Total CVEs: {len(ranked_cves)}\n"
                
                if tech in most_least_by_tech:
                    most = most_least_by_tech[tech]['most_severe']
                    least = most_least_by_tech[tech]['least_severe']
                    context += f"  - Most Severe: {most['cve_id']} (Risk: {most['risk_score']:.2f}/10, {most['risk_level']})\n"
                    context += f"  - Least Severe: {least['cve_id']} (Risk: {least['risk_score']:.2f}/10, {least['risk_level']})\n"
                context += "\n"
            
            prompt = f"""You are a helpful cybersecurity risk assessment expert. Answer the user's question directly and conversationally, like ChatGPT.

User Question: {question}

Risk Assessment Data:
{context}

Instructions:
- Answer ONLY what the user asked - be direct and conversational
- If they asked about risk, tell them the risk level and key findings
- If they asked about specific technologies, address each one
- Keep it concise and natural - no tables, no extra formatting
- Don't repeat information unnecessarily
- If multiple technologies were assessed, mention all of them
- Focus on what matters most based on the question

Answer:"""

            messages = [
                SystemMessage(content="You are a helpful cybersecurity risk assessment expert. Answer questions directly and conversationally, like ChatGPT. Only provide what's asked, nothing extra."),
                HumanMessage(content=prompt)
            ]
            
            response = self.llm.invoke(messages)
            return response.content.strip()
            
        except Exception as e:
            # Fallback to simple summary
            tech_names = ", ".join([tech.title() for tech in reports_by_tech.keys()])
            return f"Risk assessment completed for {tech_names}. Review the data for details."
    
    def query_risk(self, question, tech_stack=None, silent=False):
        """
        Query risk assessment using natural language.
        Generates separate reports for each tech stack when multiple are detected.
        Supports follow-up questions and multiple tech stacks.
        
        Args:
            question: Natural language question (e.g., "What's the risk of Jenkins and Python vulnerabilities?")
            tech_stack: List of technologies (optional, can be extracted from question)
            silent: If True, suppress all print output (default: False)
        
        Returns:
            dict with 'answer' (str), 'assessments' (list), 'ranked_cves' (DataFrame), 'reports_by_tech' (dict), etc.
        """
        from Agents.cve_search_agent import CVESearchAgent
        from RAG_PIPELINE.vector_search import extract_all_technologies, parse_query_intent
        
        if not question or not question.strip():
            return {
                "answer": "No question provided for risk assessment.",
                "assessments": [],
                "ranked_cves": None,
                "summary": "No question provided.",
                "reports_by_tech": {}
            }
        
        # Parse query intent to detect if user asked for a specific number
        intent = parse_query_intent(question)
        requested_limit = intent.get('limit')  # Will be None if no number mentioned
        
        # Determine top_k: use requested number if specified, otherwise use very high number to get all CVEs
        if requested_limit is not None:
            top_k = requested_limit  # User asked for specific number (e.g., "top 10", "100 CVEs")
        else:
            top_k = 10000  # No number mentioned - get all CVEs
        
        # Check if this is a follow-up question
        is_followup = self._is_followup_question(question)
        
        # If follow-up and we have previous assessments, reuse them
        if is_followup and self.previous_assessments is not None:
            if not silent:
                print("\n[INFO] Detected follow-up question - using previous assessment...")
            answer = self._answer_followup_question(question, self.previous_assessments)
            return {
                "answer": answer,
                "assessments": self.previous_assessments.to_dict('records'),
                "ranked_cves": self.previous_assessments,
                "summary": "Using previous risk assessment.",
                "reports_by_tech": {}
            }
        
        # Initialize CVE Search Agent if not already done
        if not hasattr(self, '_cve_agent'):
            self._cve_agent = CVESearchAgent(top_k=10000, provider="openai")  # High default, but will be overridden by top_k parameter
        
        # Extract tech stack from question if not provided
        if not tech_stack:
            tech_stack = extract_all_technologies(question)
            if not tech_stack:
                # Fallback to simple keyword matching
                question_lower = question.lower()
                tech_keywords = ['jenkins', 'python', 'docker', 'apache', 'nginx', 'kubernetes', 
                                'java', 'javascript', 'node', 'mysql', 'postgresql', 'redis',
                                'terraform', 'ansible', 'gitlab', 'github', 'mongodb', 'elasticsearch',
                                'snowflake', 'microsoft']
                tech_stack = [tech for tech in tech_keywords if tech in question_lower]
        
        # Suppress output during processing
        f = io.StringIO()
        with redirect_stdout(f):
            # If multiple tech stacks, generate separate reports for each
            if tech_stack and len(tech_stack) > 1:
                reports_by_tech = {}
                all_assessments = []
                all_ranked_cves = []
                
                # Calculate top_k per tech if limit was specified
                if requested_limit is not None:
                    top_k_per_tech = max(1, requested_limit // len(tech_stack))  # Distribute evenly
                else:
                    top_k_per_tech = 10000  # Get all CVEs for each tech
                
                for tech in tech_stack:
                    # Search for CVEs for this specific tech - use calculated top_k
                    tech_query = f"{tech} vulnerabilities"
                    search_result = self._cve_agent.search_cves(tech_query, top_k=top_k_per_tech)
                    
                    if search_result['cves'] is None or len(search_result['cves']) == 0:
                        reports_by_tech[tech] = {
                            "answer": f"No CVEs found for {tech}.",
                            "assessments": [],
                            "ranked_cves": None,
                            "summary": f"No CVEs found for {tech}."
                        }
                        continue
                    
                    # Assess risk for this tech (silent mode)
                    risk_result = self.assess_risk(
                        cves_df=search_result['cves'],
                        tech_stack=[tech],
                        use_llm=False,  # Don't use LLM for individual reports
                        silent=True
                    )
                    
                    reports_by_tech[tech] = {
                        "answer": None,  # Not needed for clean format
                        "assessments": risk_result['assessments'],
                        "ranked_cves": risk_result['ranked_cves'],
                        "summary": risk_result['summary'],
                        "by_tech": risk_result['by_tech'],
                        "detailed_explanation": None
                    }
                    
                    all_assessments.extend(risk_result['assessments'])
                    if risk_result['ranked_cves'] is not None:
                        all_ranked_cves.append(risk_result['ranked_cves'])
                
                # Combine all CVEs for overall ranking
                if all_ranked_cves:
                    combined_ranked = pd.concat(all_ranked_cves, ignore_index=True)
                    combined_ranked = combined_ranked.sort_values('overall_risk_score', ascending=False)
                    combined_ranked['rank'] = range(1, len(combined_ranked) + 1)
                    
                    # If user asked for specific number, limit the combined results
                    if requested_limit is not None:
                        combined_ranked = combined_ranked.head(requested_limit)
                else:
                    combined_ranked = None
                
                # Calculate most/least severe for direct answer
                most_least_by_tech = {}
                for tech, report in reports_by_tech.items():
                    ranked_cves = report.get('ranked_cves')
                    if ranked_cves is not None and len(ranked_cves) > 0:
                        most_least_by_tech[tech] = {
                            'most_severe': {
                                'cve_id': ranked_cves.iloc[0]['cve_id'],
                                'risk_score': ranked_cves.iloc[0]['overall_risk_score'],
                                'risk_level': ranked_cves.iloc[0]['risk_level'],
                                'title': ranked_cves.iloc[0].get('title', 'N/A')
                            },
                            'least_severe': {
                                'cve_id': ranked_cves.iloc[-1]['cve_id'],
                                'risk_score': ranked_cves.iloc[-1]['overall_risk_score'],
                                'risk_level': ranked_cves.iloc[-1]['risk_level'],
                                'title': ranked_cves.iloc[-1].get('title', 'N/A')
                            }
                        }
                
                # Generate table format instead of direct answer
                clean_format = self._generate_clean_table_format(reports_by_tech)
                
                # Store in conversation history
                self.conversation_history.append({
                    "question": question,
                    "reports_by_tech": reports_by_tech,
                    "tech_stack": tech_stack
                })
                
                if len(self.conversation_history) > 5:
                    self.conversation_history = self.conversation_history[-5:]
                
                return {
                    "answer": clean_format['conclusion'],  # Keep conclusion for text answer if needed
                    "assessments": all_assessments,
                    "ranked_cves": combined_ranked,
                    "summary": f"Generated {len(tech_stack)} separate risk assessment reports.",
                    "by_tech": reports_by_tech,
                    "reports_by_tech": reports_by_tech,
                    "clean_table": clean_format['table'],  # Add table
                    "most_least_severe": clean_format['most_least_severe']  # Add most/least severe
                }
            
            # Single tech stack or no tech stack detected
            search_result = self._cve_agent.search_cves(question, top_k=top_k)  # Use calculated top_k
            
            if search_result['cves'] is None or len(search_result['cves']) == 0:
                return {
                    "answer": f"I couldn't find any CVEs related to your question: '{question}'. Please try a different query.",
                    "assessments": [],
                    "ranked_cves": None,
                    "summary": "No CVEs found.",
                    "reports_by_tech": {}
                }
            
            # Assess risk (silent mode)
            risk_result = self.assess_risk(
                cves_df=search_result['cves'],
                tech_stack=tech_stack if tech_stack else None,
                use_llm=True,
                silent=True
            )
            
            # For single tech, generate table format
            if tech_stack:
                tech = tech_stack[0]
                reports_by_tech = {tech: {
                    "ranked_cves": risk_result['ranked_cves'],
                    "summary": risk_result['summary']
                }}
                # Generate table format
                clean_format = self._generate_clean_table_format(reports_by_tech)
            else:
                # No tech stack - create simple format
                if risk_result['ranked_cves'] is not None and len(risk_result['ranked_cves']) > 0:
                    # Create a generic report
                    reports_by_tech = {"General": {
                        "ranked_cves": risk_result['ranked_cves'],
                        "summary": risk_result['summary']
                    }}
                    clean_format = self._generate_clean_table_format(reports_by_tech)
                else:
                    clean_format = {
                        "table": "No CVEs found.",
                        "most_least_severe": {},
                        "conclusion": risk_result['summary']
                    }
            
            # Store in conversation history
            self.conversation_history.append({
                "question": question,
                "risk_assessment": risk_result,
                "tech_stack": tech_stack
            })
            
            if len(self.conversation_history) > 5:
                self.conversation_history = self.conversation_history[-5:]
            
            return {
                "answer": clean_format.get('conclusion', risk_result['summary']),
                "assessments": risk_result['assessments'],
                "ranked_cves": risk_result['ranked_cves'],
                "summary": risk_result['summary'],
                "by_tech": risk_result['by_tech'],
                "detailed_explanation": risk_result['detailed_explanation'],
                "reports_by_tech": reports_by_tech if tech_stack else {},
                "clean_table": clean_format.get('table', ''),  # Add table
                "most_least_severe": clean_format.get('most_least_severe', {})  # Add most/least severe
            }
    
    def _is_followup_question(self, question):
        """
        Check if question is a follow-up to previous assessment.
        
        Args:
            question: User's question
        
        Returns:
            bool: True if follow-up question
        """
        question_lower = question.lower()
        
        followup_phrases = [
            "tell me more", "more about", "what about", "that one", "the one",
            "you mentioned", "you said", "from above", "from previous",
            "from the list", "which one", "the first", "the second",
            "the last", "that cve", "this cve", "those cves", "these cves",
            "about it", "about that", "regarding that", "concerning that",
            "how about", "what's the risk of", "assess", "evaluate"
        ]
        
        # Check if question references previous assessment
        if any(phrase in question_lower for phrase in followup_phrases):
            return True
        
        # Check if question asks about specific CVE ID
        import re
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        if re.search(cve_pattern, question, re.IGNORECASE):
            return True
        
        return False
    
    def _answer_followup_question(self, question, previous_assessments):
        """
        Answer follow-up question using previous assessment.
        
        Args:
            question: Follow-up question
            previous_assessments: DataFrame with previous risk assessments
        
        Returns:
            Answer string
        """
        try:
            # Extract CVE ID if mentioned
            import re
            cve_pattern = r'CVE-\d{4}-\d{4,7}'
            cve_ids = re.findall(cve_pattern, question, re.IGNORECASE)
            
            # Prepare context from previous assessment
            context = "Previous Risk Assessment Results:\n\n"
            
            if cve_ids:
                # Filter to specific CVEs
                filtered = previous_assessments[previous_assessments['cve_id'].isin(cve_ids)]
                if len(filtered) > 0:
                    for idx, row in filtered.iterrows():
                        context += f"{row['cve_id']}:\n"
                        context += f"  - {row['cvss_explanation']}\n"
                        context += f"  - {row['epss_explanation']}\n"
                        context += f"  - Overall Risk: {row['overall_risk_score']:.2f}/10 ({row['risk_level']})\n\n"
            else:
                # Show top 5 from previous assessment
                top_5 = previous_assessments.head(5)
                for idx, row in top_5.iterrows():
                    context += f"{row['rank']}. {row['cve_id']}: Risk {row['overall_risk_score']:.2f}/10 ({row['risk_level']})\n"
            
            # Add conversation history
            conversation_context = ""
            if self.conversation_history:
                for item in self.conversation_history[-2:]:
                    if "question" in item and "answer" in item:
                        conversation_context += f"Previous Q: {item['question']}\nPrevious A: {item['answer'][:150]}...\n\n"
            
            prompt = f"""Answer the user's follow-up question about the previous risk assessment.

{conversation_context}{context}

User Question: {question}

Answer directly and helpfully based on the previous assessment."""
            
            messages = [
                SystemMessage(content="You are a helpful cybersecurity risk assessment expert. Answer follow-up questions naturally."),
                HumanMessage(content=prompt)
            ]
            
            response = self.llm.invoke(messages)
            return response.content
            
        except Exception as e:
            print(f"[WARNING] Follow-up answer generation failed: {e}")
            return "I can help answer questions about the previous risk assessment. What would you like to know?"
    
    def _generate_tech_report(self, tech, risk_result, cves_df):
        """
        Generate a focused risk assessment report for a specific technology.
        
        Args:
            tech: Technology name
            risk_result: Risk assessment results
            cves_df: DataFrame with CVEs
        
        Returns:
            Report string
        """
        try:
            top_5 = risk_result['ranked_cves'].head(5) if risk_result['ranked_cves'] is not None else None
            
            context = f"Technology: {tech}\n"
            context += f"Found {len(cves_df)} CVEs and assessed their risk.\n\n"
            
            if top_5 is not None and len(top_5) > 0:
                context += "Top Risk CVEs:\n"
                for idx, row in top_5.iterrows():
                    context += f"  {row['rank']}. {row['cve_id']}: Risk Score {row['overall_risk_score']:.2f}/10 ({row['risk_level']})\n"
                    context += f"     - {row['cvss_explanation']}\n"
                    context += f"     - {row['epss_explanation']}\n\n"
            
            context += f"\nSummary: {risk_result['summary']}\n"
            
            if risk_result['detailed_explanation']:
                context += f"\nDetailed Analysis:\n{risk_result['detailed_explanation']}\n"
            
            prompt = f"""Generate a concise risk assessment report for {tech} vulnerabilities.

{context}

Provide:
1. Overall risk summary for {tech}
2. Top priority CVEs that need immediate attention
3. Actionable recommendations specific to {tech}

Keep it focused and actionable. Do NOT show formulas or calculations."""
            
            messages = [
                SystemMessage(content="You are a cybersecurity risk assessment expert. Generate clear, actionable reports without showing calculations."),
                HumanMessage(content=prompt)
            ]
            
            response = self.llm.invoke(messages)
            return response.content
            
        except Exception as e:
            print(f"[WARNING] Tech report generation failed: {e}")
            return f"Risk Assessment for {tech}:\n\n{risk_result['summary']}"
    
    def _generate_overall_summary(self, reports_by_tech, combined_ranked):
        """
        Generate overall summary when multiple tech stacks are assessed.
        
        Args:
            reports_by_tech: Dict mapping tech names to their reports
            combined_ranked: DataFrame with all CVEs ranked together
        
        Returns:
            Overall summary string
        """
        try:
            context = f"Risk Assessment Reports for {len(reports_by_tech)} Technologies:\n\n"
            
            for tech, report in reports_by_tech.items():
                context += f"{tech.upper()}:\n"
                context += f"  Summary: {report['summary']}\n"
                if report.get('ranked_cves') is not None and len(report['ranked_cves']) > 0:
                    top_3 = report['ranked_cves'].head(3)
                    context += f"  Top 3 CVEs:\n"
                    for idx, row in top_3.iterrows():
                        context += f"    - {row['cve_id']}: Risk {row['overall_risk_score']:.2f}/10 ({row['risk_level']})\n"
                context += "\n"
            
            if combined_ranked is not None and len(combined_ranked) > 0:
                context += f"\nOverall Top 5 Highest Risk CVEs Across All Technologies:\n"
                top_5_all = combined_ranked.head(5)
                for idx, row in top_5_all.iterrows():
                    context += f"  {row['rank']}. {row['cve_id']}: Risk {row['overall_risk_score']:.2f}/10 ({row['risk_level']})\n"
            
            prompt = f"""Generate an overall summary of risk assessments across multiple technologies.

{context}

Provide:
1. Overall risk summary across all technologies
2. Key findings and priorities
3. Cross-technology recommendations

Keep it concise. Do NOT show formulas or calculations."""
            
            messages = [
                SystemMessage(content="You are a cybersecurity risk assessment expert. Generate clear summaries without showing calculations."),
                HumanMessage(content=prompt)
            ]
            
            response = self.llm.invoke(messages)
            return response.content
            
        except Exception as e:
            print(f"[WARNING] Overall summary generation failed: {e}")
            return f"Risk assessment completed for {len(reports_by_tech)} technologies."
    
    def _generate_conversational_answer(self, question, risk_result, cves_df):
        """
        Generate a conversational answer to the user's question about risk.
        Includes conversation history for context.
        
        Args:
            question: User's original question
            risk_result: Risk assessment results
            cves_df: DataFrame with CVEs
        
        Returns:
            Conversational answer string
        """
        try:
            # Prepare context
            top_5 = risk_result['ranked_cves'].head(5) if risk_result['ranked_cves'] is not None else None
            
            context = f"User Question: {question}\n\n"
            context += f"Found {len(cves_df)} CVEs and assessed their risk.\n\n"
            
            if top_5 is not None and len(top_5) > 0:
                context += "Top Risk CVEs:\n"
                for idx, row in top_5.iterrows():
                    context += f"  {row['rank']}. {row['cve_id']}: Risk Score {row['overall_risk_score']:.2f}/10 ({row['risk_level']})\n"
                    context += f"     - {row['cvss_explanation']}\n"
                    context += f"     - {row['epss_explanation']}\n\n"
            
            context += f"\nSummary: {risk_result['summary']}\n"
            
            if risk_result['detailed_explanation']:
                context += f"\nDetailed Analysis:\n{risk_result['detailed_explanation']}\n"
            
            # Add conversation history for context
            conversation_context = ""
            if self.conversation_history:
                for item in self.conversation_history[-2:]:  # Last 2 conversations
                    if "question" in item and "answer" in item:
                        conversation_context += f"Previous Q: {item['question']}\nPrevious A: {item['answer'][:200]}...\n\n"
            
            prompt = f"""You are a cybersecurity risk assessment expert. Answer the user's question about CVE risk in a conversational, helpful way.

{conversation_context}{context}

Answer the user's question directly and naturally. Include:
- Key risk findings
- Top priority CVEs
- Actionable recommendations

Keep it conversational and easy to understand. Use previous conversation context if relevant.
Do NOT show formulas or calculation steps - only show final risk scores and explanations."""
            
            messages = [
                SystemMessage(content="You are a helpful cybersecurity risk assessment expert. Answer questions naturally and conversationally."),
            ]
            
            # Add conversation history as messages
            if self.conversation_history:
                for item in self.conversation_history[-2:]:
                    if "question" in item and "answer" in item:
                        messages.append(HumanMessage(content=f"Previous question: {item['question']}"))
                        messages.append(SystemMessage(content=f"Previous answer: {item['answer'][:300]}..."))
            
            messages.append(HumanMessage(content=prompt))
            
            response = self.llm.invoke(messages)
            return response.content
            
        except Exception as e:
            print(f"[WARNING] Conversational answer generation failed: {e}")
            # Fallback to summary
            return f"Risk Assessment Summary:\n\n{risk_result['summary']}\n\n{risk_result.get('detailed_explanation', '')}"
    
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
        self.previous_assessments = None

if __name__ == "__main__":
    # Interactive Risk Assessment Agent
    agent = RiskAssessmentAgent()
    
    print("="*80)
    print("RISK ASSESSMENT AGENT - Interactive Mode")
    print("="*80)
    print("\nAsk questions about CVE risk assessment. Type 'quit', 'exit', or 'q' to stop.")
    print("Type 'clear' or 'reset' to clear conversation history.")
    print("-"*80)
    
    while True:
        try:
            # Get user question
            question = input("\nYou: ").strip()
            
            if question.lower() in ['quit', 'exit', 'q']:
                print("\nGoodbye!")
                break
            
            if question.lower() in ['clear', 'reset']:
                agent.clear_history()
                print("\n[INFO] Conversation history cleared.\n")
                continue
            
            if not question:
                continue  # Just skip empty input, don't print anything
            
            # Query risk assessment (silent mode)
            result = agent.query_risk(question, silent=True)
            
            # Display table format (like the image)
            print("\n" + "="*80)
            print("RISK ASSESSMENT REPORT")
            print("="*80)
            
            # Show table
            if result.get('clean_table'):
                print("\nTECH STACK RISK METRICS:")
                print("-"*80)
                print(result['clean_table'])
            
            # Show most/least severe per tech
            if result.get('most_least_severe'):
                print("\n" + "="*80)
                print("MOST & LEAST SEVERE CVEs BY TECH STACK:")
                print("="*80)
                for tech, data in result['most_least_severe'].items():
                    print(f"\n{tech.upper()}:")
                    print(f"  Most Severe: {data['most_severe']['cve_id']}")
                    print(f"    - Risk Score: {data['most_severe']['risk_score']:.2f}/10 ({data['most_severe']['risk_level']})")
                    print(f"    - Title: {data['most_severe']['title']}")
                    print(f"\n  Least Severe: {data['least_severe']['cve_id']}")
                    print(f"    - Risk Score: {data['least_severe']['risk_score']:.2f}/10 ({data['least_severe']['risk_level']})")
                    print(f"    - Title: {data['least_severe']['title']}")
            
            print("\n" + "-"*80)

        except KeyboardInterrupt:
            print("\n\n[INFO] Interrupted by user")
            break
        except Exception as e:
            print(f"\n[ERROR] An error occurred: {e}")
            import traceback
            traceback.print_exc()
            print("\n" + "-"*80)

