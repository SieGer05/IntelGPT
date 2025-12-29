import os
import json
import re
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List 
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
class Message(BaseModel):
   role: str
   content: str

class QueryRequest(BaseModel):
   query: str
   history: List[Message] = []

class QueryResponse(BaseModel):
   answer: str
   sources: list[str]

# ENDPOINT
@app.post("/chat", response_model=QueryResponse)
async def chat_endpoint(request: QueryRequest):
   try:
      user_query = request.query.strip()
      history = request.history

      if not user_query:
         raise HTTPException(status_code=400, detail="Query cannot be empty")
      
      # Step 1: ROUTER (THE BRAIN) 
      print(f"[ROUTER] Analyzing intent for: {user_query}")
      router_prompt = f"""
         Analyze the following user query: "{user_query}"
         
         Return a JSON object with these fields:
         1. "intent": "technical" (if it's about cybersecurity, attacks, MITRE, or definitions) OR "general" (if it's greeting, small talk, or thanks).
         2. "safe": true (if safe) or false (if asking for malware code/exploits).
         
         Example JSON: {{"intent": "general", "safe": true}}
      """

      router_completion = groq_client.chat.completions.create(
         messages=[
            {"role": "system", "content": "You are a helpful classifier. Output JSON only."},
            {"role": "user", "content": router_prompt}
         ],
         model=GROQ_MODEL,
         response_format={"type": "json_object"}
      )

      analysis = json.loads(router_completion.choices[0].message.content)
      intent = analysis.get("intent", "general")
      is_safe = analysis.get("safe", True)

      if not is_safe:
         return QueryResponse(
            answer="I cannot fulfill this request because it violates safety guidelines regarding exploit generation.",
            sources=[]
         )
      
      context_text = ""
      sources = []
      system_prompt = ""

      # Step 2: Branching
      if intent == "technical":
         # >> PATH A: TECHNICAL (RAG)
         
         # --- ENHANCEMENT START: Contextualization ---
         # Default search query is the user query
         search_query = user_query
         
         # If we have history, rewrite the query to include context
         if history:
            print("[REWRITE] Contextualizing query based on history...")
            history_block = "\n".join([f"{msg.role}: {msg.content}" for msg in history])
            
            rewrite_prompt = f"""
            Given the conversation history, rewrite the user's last query to be a standalone search query.
            Replace pronouns (like "it", "this attack", "that") with the specific terms from the history.
            Output ONLY the rewritten query string. Nothing else.
            
            History:
            {history_block}
            
            User Query: {user_query}
            
            Rewritten Query:
            """
            
            rewrite_completion = groq_client.chat.completions.create(
            messages=[{"role": "user", "content": rewrite_prompt}],
            model=GROQ_MODEL,
            temperature=0.1
            )
            
            search_query = rewrite_completion.choices[0].message.content.strip()
            print(f"[REWRITE] Original: '{user_query}' -> New: '{search_query}'")
         # --- ENHANCEMENT END ---

         print(f"[PATH] Technical Query -> Searching Database for: {search_query}")

         # --- SMART RETRIEVAL LOGIC START ---
         # Detect specific IDs (CVE or MITRE) to use deterministic filtering
         cve_match = re.search(r"(CVE-\d{4}-\d{4,7})", search_query, re.IGNORECASE)
         mitre_match = re.search(r"(T\d{4}(?:\.\d{3})?)", search_query, re.IGNORECASE)
         
         where_filter = None
         
         if cve_match:
            target_id = cve_match.group(1).upper()
            print(f"[SMART SEARCH] Exact CVE detected: {target_id}")
            where_filter = {"external_id": target_id}
             
         elif mitre_match:
            target_id = mitre_match.group(1).upper()
            print(f"[SMART SEARCH] Exact MITRE ID detected: {target_id}")
            where_filter = {"external_id": target_id}

         # Prepare Vector Search
         query_vector = embedding_model.encode([search_query]).tolist()
         results = {'documents': [], 'metadatas': []}

         # Execute Query
         if where_filter:
            # Case 1: Smart Filter Active
            results = collection.query(
               query_embeddings=query_vector, 
               n_results=5, 
               where=where_filter
            )
            # Fallback if filter returns nothing (e.g. typo in ID or ID not in DB)
            if not results['documents'] or not results['documents'][0]:
               print("[SMART SEARCH] ID not found in DB, falling back to semantic search...")
               results = collection.query(query_embeddings=query_vector, n_results=10)
         else:
            # Case 2: Standard Semantic Search (Broad search)
            results = collection.query(query_embeddings=query_vector, n_results=10)
         # --- SMART RETRIEVAL LOGIC END ---

         if results['documents'] and results['documents'][0]:
            for i in range(len(results['documents'][0])):
               doc = results['documents'][0][i]
               meta = results['metadatas'][0][i]
               
               source_id = f"{meta['name']} ({meta.get('external_id', 'N/A')})"
               # Prevent duplicates in source list
               if source_id not in sources:
                  sources.append(source_id)
               context_text += f"---\nSOURCE: {source_id}\nCONTENT: {doc}\n"
         else:
            context_text = "No specific cybersecurity documents found in database."
         
         system_prompt = f"""
         You are a Cyber Threat Intelligence Expert.
         Use ONLY the following context to answer the user's question.
         If the answer is not in the context, say "I don't have enough information in my database."
         
         CONTEXT:
         {context_text}
         
         Keep the answer technical, concise, and structured.
         """
      
      else:
         # >> PATH B: GENERAL (Chit-Chat)
         print("[PATH] General Query -> Skipping Database.")
         system_prompt = "You are a helpful Cyber Security Assistant. Be polite, professional, and concise. Do not make up technical facts."
      
      # Step 3: Generation WITH MEMORY
      # 1. On commence par le Prompt Système
      messages_payload = [
         {"role": "system", "content": system_prompt}
      ]
      
      # 2. On insère l'historique (les 6 derniers messages envoyés par le frontend)
      for msg in history:
         messages_payload.append({"role": msg.role, "content": msg.content})
          
      # 3. On ajoute la question actuelle de l'utilisateur
      messages_payload.append({"role": "user", "content": user_query})

      chat_completion = groq_client.chat.completions.create(
         messages=messages_payload, 
         model=GROQ_MODEL,
         temperature=0.0,
      )

      response_text = chat_completion.choices[0].message.content

      return QueryResponse(
         answer=response_text,
         sources=sources[:5] 
      )

   except Exception as e:
      print(f"[ERROR] {e}")
      raise HTTPException(status_code=500, detail=str(e))