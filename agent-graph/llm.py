import os

from dotenv import load_dotenv

load_dotenv()

enable_thinking = os.getenv("ENABLE_THINKING", "0") == "1"

if os.getenv("LLM_BACKEND", "openai").strip().lower() == "ollama":
    from langchain_ollama import ChatOllama

    _num_ctx = os.getenv("OLLAMA_NUM_CTX")
    llm = ChatOllama(
        model=os.getenv("OLLAMA_MODEL", "qwen3:8b"),
        base_url=os.getenv("OLLAMA_URL", "http://localhost:11434"),
        temperature=0,
        reasoning=enable_thinking,
        **({"num_ctx": int(_num_ctx)} if _num_ctx else {}),
    )
else:
    from langchain_openai import ChatOpenAI
    from pydantic import SecretStr

    llm = ChatOpenAI(
        model=os.getenv("OPENAI_MODEL", "huihui-qwen3.8-27b-abliterated"),
        base_url=os.getenv("API_URL", "https://slop.undo.it/v1"),
        api_key=SecretStr(os.getenv("API_KEY", "")),
        temperature=0,
        use_responses_api=False,
        extra_body={"chat_template_kwargs": {"enable_thinking": enable_thinking}},
    )
