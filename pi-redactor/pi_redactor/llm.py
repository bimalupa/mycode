"""Azure GenAI Lab clients (OpenAI-compatible gateway) with an optional native Azure OpenAI mode."""
from functools import lru_cache

import httpx

from .config import settings


@lru_cache(maxsize=1)
def get_chat_llm():
    if not settings.llm_enabled:
        return None
    if settings.llm_provider == "azure":
        from langchain_openai import AzureChatOpenAI
        return AzureChatOpenAI(azure_endpoint=settings.llm_base_url, api_key=settings.llm_api_key,
                               azure_deployment=settings.llm_model, api_version=settings.azure_api_version,
                               temperature=0, timeout=90, max_retries=2,
                               http_client=httpx.Client(verify=settings.verify_ssl))
    from langchain_openai import ChatOpenAI
    return ChatOpenAI(base_url=settings.llm_base_url, api_key=settings.llm_api_key,
                      model=settings.llm_model, temperature=0, timeout=90, max_retries=2,
                      http_client=httpx.Client(verify=settings.verify_ssl))


@lru_cache(maxsize=1)
def get_embeddings():
    if not settings.llm_enabled:
        return None
    if settings.llm_provider == "azure":
        from langchain_openai import AzureOpenAIEmbeddings
        return AzureOpenAIEmbeddings(azure_endpoint=settings.llm_base_url, api_key=settings.llm_api_key,
                                     azure_deployment=settings.embed_model,
                                     api_version=settings.azure_api_version,
                                     http_client=httpx.Client(verify=settings.verify_ssl))
    from langchain_openai import OpenAIEmbeddings
    return OpenAIEmbeddings(base_url=settings.llm_base_url, api_key=settings.llm_api_key,
                            model=settings.embed_model, check_embedding_ctx_length=False,
                            http_client=httpx.Client(verify=settings.verify_ssl))
