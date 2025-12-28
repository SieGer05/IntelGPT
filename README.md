<p align="center">
  <img src="./docs/intelGPT.png" alt="intelGPT Logo" width="200"/>
</p>

<h1 align="center">I N T E L G P T</h1>

<h4 align="center"><b>intelGPT</b> is a secure RAG-powered Cyber Threat Intelligence assistant grounded in MITRE ATT&CK data, designed to deliver reliable and safe responses.</h4>

<p align="center">
   <img src="https://img.shields.io/badge/React-20232A?style=for-the-badge&logo=react&logoColor=61DAFB">
   <img src="https://img.shields.io/badge/Python-FFD43B?style=for-the-badge&logo=python&logoColor=blue">
   <img src="https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi">
   <img src="https://img.shields.io/badge/javascript-%23323330.svg?style=for-the-badge&logo=javascript&logoColor=%23F7DF1E">
   <img src="https://img.shields.io/badge/tailwindcss-%2338B2AC.svg?style=for-the-badge&logo=tailwind-css&logoColor=white">
   <img src="https://img.shields.io/badge/npm-CB3837?style=for-the-badge&logo=npm&logoColor=white">
   <img src="https://img.shields.io/badge/huggingface-%23FFD21E.svg?style=for-the-badge&logo=huggingface&logoColor=white">

</p>

## **Overview**

**intelGPT** is a specialized LLM application engineered for Cyber Threat Intelligence (CTI). Unlike generic AI models, intelGPT prioritizes accuracy and security by grounding all technical responses in verified MITRE ATT&CK data.

The system features a **Secure RAG (Retrieval-Augmented Generation)** architecture that prevents hallucinations and enforces strict security guardrails to mitigate risks such as prompt injection and social engineering.

## **Security Features**

To make the RAG pipeline more secure and reliable, intelGPT implements several defense mechanisms:

1.  **Input Guardrails (Router):** An intelligent classification layer analyzes every user query before it reaches the core logic. It detects and blocks malicious intents (e.g., malware generation requests, jailbreaks) and routes benign queries appropriately.

2.  **Contextual Grounding:** Technical answers are strictly generated based on retrieved documents from the local vector database (ChromaDB). If the information is not present in the verified dataset, the system is instructed to admit ignorance rather than hallucinating facts.

3.  **Sanitized Memory Window:** The conversation history uses a "Sliding Window" approach. Only the most recent relevant context is retained, and it is sanitized to prevent prompt pollution or token overflow attacks.


## **Installation Guide**

This project requires **Python 3.11.14** and **Node.js**. We utilize **uv** for ultra-fast Python package management.

### 1. Clone the Repository

```bash
git clone https://github.com/SieGer05/IntelGPT.git
cd IntelGPT
```

### 2. Backend Setup
Navigate to the backend directory to set up the Python environment and database.

> **Step A:** Initialize Virtual Environment with uv

```bash
uv venv --python 3.11
```

> **Step B:** Activate the Environment

- **Windows:** .venv\Scripts\activate
- **Linux/Mac:** source .venv/bin/activate

> **Step C:** Install Dependencies

```bash
uv pip install fastapi uvicorn pydantic chromadb sentence-transformers groq python-dotenv requests
```

> **Step D:** Ingest Data (First Run Only)

Run the ingestion script from the project root to populate the vector database with MITRE ATT&CK data.

```bash
# From project root
python ingest_data.py
```

### 3. Frontend Setup
Open a new terminal window and navigate to the frontend directory.

```bash
cd frontend
npm install
```

## **Configuration**

You must configure the environment variables for the backend to communicate with the LLM provider.

1. Navigate to the backend/ directory.
2. Create a file named .env.
3.    Add your API key configuration.

**backend/.env.example**

```bash
# Groq API Key for LLM Inference (Llama 3.3)
GROQ_API_KEY=gsk_your_api_key_here

# Optional: Path to ChromaDB (Default is ./chroma_db)
# DB_PATH=./chroma_db
```

## **Running the Application**

To run the full stack, you need to run the backend API and the frontend client simultaneously in separate terminals.

> **Terminal 1:** Backend API

```bash
cd backend
# Ensure your venv is active
uvicorn main:app --reload
```

The API will start at *`http://127.0.0.1:8000`*.

> **Terminal 2:** Frontend Client

The User Interface will be accessible at *`http://localhost:5173`*.

## **Development Status**
**Note:** This project is currently Under Development.

Functionality is subject to change. The current release is a working prototype demonstrating the Secure RAG architecture. Future updates will include multi-document ingestion, advanced role-based access control, and dockerized deployment.