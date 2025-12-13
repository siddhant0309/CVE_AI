import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import os
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage
import base64


load_dotenv()

class TechStackDetectionAgent:
    """
    Agent that detects technology stack from architecture images.
    Uses GPT-4 Vision to analyze images and extract technologies.
    """
    
    def __init__(self, model="gpt-4o", temperature=0.3):
        """
        Initialize the Tech Stack Detection Agent.
        
        Args:
            model: OpenAI model to use (default: gpt-4o for vision)
            temperature: Model temperature (default: 0.3 for more factual)
        """
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY not found in environment variables")
        
        self.llm = ChatOpenAI(
            model=model,
            temperature=temperature,
            api_key=api_key
        )
        self.conversation_history = []  # Individual agent memory
    
    def _encode_image(self, image_path):
        """
        Encode image to base64 for API.
        
        Args:
            image_path: Path to image file
        
        Returns:
            Tuple of (base64_string, mime_type)
        """
        # Detect image format from extension
        ext = os.path.splitext(image_path)[1].lower()
        mime_types = {
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.png': 'image/png',
            '.gif': 'image/gif',
            '.webp': 'image/webp'
        }
        mime_type = mime_types.get(ext, 'image/jpeg')  # Default to JPEG
        
        with open(image_path, "rb") as image_file:
            base64_str = base64.b64encode(image_file.read()).decode('utf-8')
        
        return base64_str, mime_type
    
    def detect_tech_stack(self, image_path):
        """
        Detect technology stack from architecture image.
        
        Args:
            image_path: Path to the architecture image
        
        Returns:
            dict with 'tech_stack' (list) and 'details' (str)
        """
        try:
            # Encode image
            base64_image, mime_type = self._encode_image(image_path)
            
            # Create prompt
            prompt = """Analyze this architecture/network diagram image and identify ALL technologies, frameworks, services, and software components visible.

IMPORTANT: Return your response in this EXACT format:

TECHNOLOGIES: Technology1, Technology2, Technology3, ...

DETAILS: [Your detailed description here]

Please identify:
- Web servers, application servers
- Databases and data stores
- Container technologies
- Cloud services and platforms
- Programming languages and runtimes
- Frameworks and libraries
- Security tools
- Any other software/technology visible in the image

Be thorough and list EVERY technology you can identify, even if it's uncommon or specialized."""
            
            # Create message with image
            message = HumanMessage(
                content=[
                    {
                        "type": "text",
                        "text": prompt
                    },
                    {
                        "type": "image_url",
                        "image_url": {
                            "url": f"data:{mime_type};base64,{base64_image}"
                        }
                    }
                ]
            )
            
            # Call LLM
            response = self.llm.invoke([message])
            answer = response.content
            
            # Extract tech stack list (simple parsing - can be improved)
            tech_stack = self._extract_tech_stack(answer)
            
            # Store in conversation history
            self.conversation_history.append({
                "input": image_path,
                "output": answer,
                "tech_stack": tech_stack
            })
            
            return {
                "tech_stack": tech_stack,
                "details": answer,
                "raw_response": answer
            }
            
        except Exception as e:
            raise Exception(f"Tech stack detection failed: {e}")
    
    def _extract_tech_stack(self, response_text):
        """
        Extract technology list from LLM response.
        Parses any technology mentioned, not just hardcoded list.
        
        Args:
            response_text: LLM response text
        
        Returns:
            List of technologies
        """
        found_techs = []
        
        # Method 1: Look for "TECHNOLOGIES:" section 
        if "TECHNOLOGIES:" in response_text.upper():
            # Extract the technologies line
            lines = response_text.split('\n')
            for i, line in enumerate(lines):
                if "TECHNOLOGIES:" in line.upper():
                    # Get the technologies line
                    tech_line = line.split("TECHNOLOGIES:")[-1].strip()
                    # Also check next line if current line is just "TECHNOLOGIES:"
                    if not tech_line and i + 1 < len(lines):
                        tech_line = lines[i + 1].strip()
                    
                    # Split by comma and clean
                    techs = [t.strip() for t in tech_line.split(',')]
                    found_techs.extend([t for t in techs if t and len(t) > 1])
                    break
        
        # Method 2: Extract from numbered/bulleted lists
        lines = response_text.split('\n')
        for line in lines:
            line = line.strip()
            # Look for numbered lists (1. Tech, 2. Tech) or bullet points (- Tech, * Tech)
            if (line and (line[0].isdigit() or line.startswith('-') or line.startswith('*')) 
                and len(line) > 3):
                # Remove numbering/bullets and extract tech name
                tech = line.split('.', 1)[-1].strip() if '.' in line else line[1:].strip()
                tech = tech.split(':')[0].strip()  # Remove description after colon
                if tech and len(tech) > 1:
                    found_techs.append(tech)
        
        # Extract from comma-separated lists
        # Look for lines with multiple commas (likely a tech list)
        for line in lines:
            if ',' in line and line.count(',') >= 2:
                # Split by comma
                techs = [t.strip() for t in line.split(',')]
                for tech in techs:
                    # Clean up (remove common words, keep tech names)
                    tech = tech.strip('.,;:')
                    if (tech and len(tech) > 1 and 
                        tech[0].isupper() and  # Tech names usually start with capital
                        tech.lower() not in ['and', 'or', 'etc', 'etc.', 'the', 'a', 'an']):
                        found_techs.append(tech)
        
        # Extract capitalized words/phrases (common tech naming pattern)
        words = response_text.split()
        i = 0
        while i < len(words):
            word = words[i].strip('.,;:()[]{}')
            # Look for capitalized words that might be tech names
            if (word and word[0].isupper() and len(word) > 2 and
                word.lower() not in ['the', 'and', 'or', 'for', 'with', 'from', 'this', 'that']):
                # Check if it's part of a multi-word tech (e.g., "Node.js", "Apache HTTP")
                tech_name = word
                if i + 1 < len(words):
                    next_word = words[i + 1].strip('.,;:()[]{}')
                    # Common patterns: "Apache HTTP", "Node.js", "AWS S3"
                    if (next_word and next_word[0].isupper() and 
                        (next_word.lower() in ['server', 'http', 'api', 's3', 'ec2'] or
                         '.' in next_word or next_word.isupper())):
                        tech_name = f"{word} {next_word}"
                        i += 1
                
                if tech_name not in found_techs and tech_name.lower() not in [t.lower() for t in found_techs]:
                    found_techs.append(tech_name)
            i += 1
        
        #  remove duplicates, common false positives
        found_techs = list(set(found_techs))
        # Remove common false positives
        false_positives = ['Image', 'Diagram', 'Architecture', 'System', 'Service', 
                          'Component', 'Application', 'Server', 'Database', 'Cloud']
        found_techs = [t for t in found_techs if t not in false_positives and 
                      t.lower() not in [fp.lower() for fp in false_positives]]
        
        return found_techs if found_techs else []
    
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

if __name__ == "__main__":
    # Test the agent
    agent = TechStackDetectionAgent()
    
    # Test with  an image (replace with your image path)
    image_path = input("Enter path to architecture image: ").strip()
    
    if os.path.exists(image_path):
        print("\nAnalyzing image...")
        result = agent.detect_tech_stack(image_path)
        
        print("\n" + "="*80)
        print("TECH STACK DETECTED:")
        print("="*80)
        print(f"\nTechnologies: {', '.join(result['tech_stack'])}")
        print(f"\nTotal: {len(result['tech_stack'])} technologies found")
        print("\n" + "="*80)
        print("DETAILS:")
        print("="*80)
        print(result['details'])
    else:
        print(f"Image not found: {image_path}")