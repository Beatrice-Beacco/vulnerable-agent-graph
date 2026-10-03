import os

from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from pydantic import SecretStr

load_dotenv()

llm_api_url = os.getenv("API_URL", "https://slop.undo.it/v1")
llm_api_key = os.getenv("API_KEY", "")

enable_thinking = os.getenv("ENABLE_THINKING", "0") == "1"

llm = ChatOpenAI(
    model="huihui-qwen3.8-27b-abliterated",
    base_url=llm_api_url,
    api_key=SecretStr(llm_api_key),
    temperature=0,
    use_responses_api=False,
    extra_body={"chat_template_kwargs": {"enable_thinking": enable_thinking}},
)
