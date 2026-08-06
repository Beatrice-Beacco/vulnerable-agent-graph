from langchain_ollama import ChatOllama

llm = ChatOllama(model="qwen3:30b", temperature=0, reasoning=False)
