import os

from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from pydantic import SecretStr

load_dotenv()

llm_api_url = os.getenv("API_URL")
llm_api_key = os.getenv("API_KEY")

llm = ChatOpenAI(
    model="vllm/qwen3.8-27b",
    base_url=llm_api_url if llm_api_url is not None else None,
    api_key=SecretStr(llm_api_key) if llm_api_key is not None else None,
    temperature=0,
)
