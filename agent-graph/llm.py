import os

from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from pydantic import SecretStr
from langchain_ollama import ChatOllama

# load_dotenv()

# llm_api_url = os.getenv("API_URL", "https://slop.undo.it/v1")
# llm_api_key = os.getenv("API_KEY", "")

# llm = ChatOpenAI(
#     model="qwen3.8-27b",
#     base_url=llm_api_url,
#     api_key=SecretStr(llm_api_key),
#     temperature=0,
#     use_responses_api=False,
#     extra_body={"chat_template_kwargs": {"enable_thinking": False}},
# )

llm = ChatOllama(
    model="qwen3:8b",
    reasoning=False,
)
