import os
from dotenv import load_dotenv
from google import genai

load_dotenv("/home/osboxes/cti/.env")
client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])

MODEL = "gemini-3.5-flash-lite"

resp = client.models.generate_content(
    model=MODEL,
    contents="次の英文を日本語に訳してください: A critical vulnerability was patched.",
)
print(resp.text)
