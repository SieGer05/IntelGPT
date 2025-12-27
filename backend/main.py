import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import chromadb
from sentence_transformers import SentenceTransformer
from groq import Groq
from dotenv import load_dotenv

# CONFIGURATION
# Load environment variables
load_dotenv()

API_KEY = os.environ.get("GROQ_API_KEY")
MODEL_NAME = "all-MiniLM-L6-v2"
DB_PATH = "../chroma_db" 
COLLECTION_NAME = "mitre_attack"
GROQ_MODEL = "llama-3.3-70b-versatile"

# APP INITIALIZATION
app = FastAPI(title="Secure RAG API")

app.add_middleware(
   CORSMiddleware,
   allow_origins=["*"], 
   allow_credentials=True,
   allow_methods=["*"],
   allow_headers=["*"],
)

# GLOBAL VARIABLES
## We load these once at startup so requests are fast
embedding_model = None
chroma_client = None
collection = None
groq_client = None

@app.on_event("startup")
async def startup_event():
   global embedding_model, chroma_client, collection, groq_client
   
   print("[INIT] Loading Models & Database...")
   if not API_KEY:
      raise ValueError("GROQ_API_KEY not found in .env file")
      
   embedding_model = SentenceTransformer(MODEL_NAME)
   chroma_client = chromadb.PersistentClient(path=DB_PATH)
   collection = chroma_client.get_collection(COLLECTION_NAME)
   groq_client = Groq(api_key=API_KEY)
   print("[READY] API is ready to accept requests.")

# DATA MODELS 
class QueryRequest(BaseModel):
   query: str

class QueryResponse(BaseModel):
   answer: str
   sources: list[str]

# ENDPOINT
@app.post("/chat", response_model=QueryResponse)
async def chat_endpoint(request: QueryRequest):
   try:
      user_query = request.query.strip()
      if not user_query:
         raise HTTPException(status_code=400, detail="Query cannot be empty")

      # 1. RETRIEVAL
      print(f"[SEARCH] Analyzing: {user_query}")
      query_vector = embedding_model.encode([user_query]).tolist()
      results = collection.query(query_embeddings=query_vector, n_results=3)

      context_text = ""
      sources = []

      if results['documents'] and results['documents'][0]:
         for i in range(len(results['documents'][0])):
            doc = results['documents'][0][i]
            meta = results['metadatas'][0][i]
            
            source_id = f"{meta['name']} ({meta.get('external_id', 'N/A')})"
            sources.append(source_id)
            context_text += f"---\nSOURCE: {source_id}\nCONTENT: {doc}\n"
      else:
         context_text = "No specific cybersecurity documents found in database."

      # 2. GENERATION 
      system_prompt = f"""
         You are a Cyber Threat Intelligence Expert.
         Use ONLY the following context to answer the user's question.
         If the answer is not in the context, say "I don't have enough information in my database."
         
         CONTEXT:
         {context_text}
         
         Keep the answer technical, concise, and structured.
      """

      chat_completion = groq_client.chat.completions.create(
         messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_query}
         ],
         model=GROQ_MODEL,
         temperature=0.0,
      )

      response_text = chat_completion.choices[0].message.content

      return QueryResponse(
         answer=response_text,
         sources=sources
      )

   except Exception as e:
      print(f"[ERROR] {e}")
      raise HTTPException(status_code=500, detail=str(e))