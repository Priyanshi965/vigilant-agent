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
    model_name: str = "llama-3.1-8b-instant"

    # Security
    injection_threshold: float = 0.8

    # Logging
    log_level: str = "INFO"

    # HuggingFace
    hf_token: str = ""

    # Authentication
    secret_key: str = "changeme"
    token_expire_hours: int = 24


@lru_cache()
def get_settings() -> Settings:
    return Settings()