import os
from dotenv import load_dotenv
from openai import OpenAI

# Load .env
load_dotenv()

# Read key from env
API_KEY = os.getenv("OPEN_AI_KEY")

if not API_KEY:
    raise ValueError("OPEN_AI_KEY not found in .env")

# Create OpenAI client once (reuse everywhere)
client = OpenAI(api_key=API_KEY)

def call_llm(prompt: str, model: str = "gpt-4.1-mini") -> str:
    """
    Call OpenAI with a prompt and return the response text.
    """

    response = client.responses.create(
        model=model,
        input=prompt
    )

    return response.output_text

print(call_llm("Say hello in one sentence."))

