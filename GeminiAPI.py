# gemini_client.py
from google import genai

# Initialize the client once
client = genai.Client(api_key="paste your API here")

MODEL_NAME = "gemini-2.0-flash-lite"

def ai_summarize(text: str) -> str:
    try:
        response = client.models.generate_content(
            model=MODEL_NAME,
            contents=text
        )
        return response.text
    except Exception as e:
        return f"AI Error: {str(e)}"
