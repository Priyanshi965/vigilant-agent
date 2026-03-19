from pydantic_settings import BaseSettings
from pydantic import ConfigDict
from functools import lru_cache


class Settings(BaseSettings):
    model_config = ConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        protected_namespaces=()
    )

    # LLM
    openai_api_key: str = "not-used"
    groq_api_key: str = ""
    model_name: str = "llama3-8b-8192"

    # Security
    injection_threshold: float = 0.8

    # Logging
    log_level: str = "INFO"


@lru_cache()
def get_settings() -> Settings:
    return Settings()