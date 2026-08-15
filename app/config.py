"""
Centralized Confi
Uses pydantic-settings for validated environment variables
"""

from pydantic_settings import BaseSettings
from functools import lru_cache

import os
from dotenv import load_dotenv
load_dotenv()

class Settings(BaseSettings):
    """"""
    # LLM Configuration
    openai_api_key: str = os.environ['OPENAI_API_KEY']
    primary_model: str = "MiniMax-M3"
    fallback_model: str = "MiniMax-M3"

    # LangSmith
    langchain_tracing_v2: bool = True
    langchain_api_key: str = os.environ['LANGSMITH_API_KEY']
    langchain_project: str = "production-api"

    # Application
    app_env: str = "development"
    log_level: str = "INFO"
    rate_limit: str = "3/minute"
    cache_ttl_seconds: int = 300
    max_retries: int = 3

    model_config = {"env_file": ".env", "extra": "ignore"}

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

@lru_cache
def get_settings() -> Settings:
    """Cached settings instance - loaded once, reused everywhere."""
    return Settings()