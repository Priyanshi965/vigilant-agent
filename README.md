# 🛡️ Vigilant Agent

An intelligent, secure, and production-ready AI agent framework. **Vigilant Agent** is designed to provide a robust proxy interface for interacting with Large Language Models (LLMs) like OpenAI and Groq, featuring built-in monitoring, containerization, and comprehensive testing.

## 🚀 Key Features
* **Multi-Model Support**: Seamlessly switch between OpenAI and Groq providers.
* **Secure Architecture**: Environment-based configuration to keep API keys safe.
* **Observability**: Integrated Prometheus configuration for real-time monitoring.
* **Containerized**: Ready for deployment via Docker and Docker Compose.
* **Reliability**: Full test suite using `pytest` to ensure agent stability.

## 🛠️ Tech Stack
* **Core**: Python 3.13+
* **LLMs**: OpenAI API, Groq Cloud
* **DevOps**: Docker, Docker Compose, Prometheus
* **Testing**: Pytest
* **Database**: SQLite (`vigilant.db`)

## 📦 Installation & Setup

1.  **Clone the Repository**
    ```powershell
    git clone [https://github.com/Priyanshi965/vigilant-agent.git](https://github.com/Priyanshi965/vigilant-agent.git)
    cd vigilant-agent
    ```

2.  **Set Up Virtual Environment**
    ```powershell
    python -m venv venv
    .\venv\Scripts\Activate.ps1
    pip install -r requirements.txt
    ```

3.  **Configure Environment Variables**
    Create a `.env` file in the root directory (do not commit this file!):
    ```env
    OPENAI_API_KEY=your_openai_key_here
    GROQ_API_KEY=your_groq_key_here
    MODEL_NAME=llama-3.1-8b-instant
    INJECTION_THRESHOLD=0.8
    HF_TOKEN=your_huggingface_token_here
    SECRET_KEY=your_secret_key
    TOKEN_EXPIRE_HOURS=24
    ```

## 🐳 Running with Docker

To launch the agent along with Prometheus monitoring:
```powershell
docker-compose up --build
