import os
import json
import re
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List 
import chromadb
from sentence_transformers import SentenceTransformer
from groq import Groq
from dotenv import load_dotenv

# Security Layer
from security import InputGuard, OutputGuard, SecurityException
from structured_logger import logger
import json
import time

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

@app.middleware("http")
async def log_requests(request: Request, call_next):
    # 1. Skip logging for the logs endpoint itself (reduce noise)
    if "api/logs" in request.url.path:
        return await call_next(request)

    start_time = time.time()
    
    # 2. CAPTURE BODY (PROMPT) safely
    # We need to read the body, but consuming it empties the stream for the actual endpoint.
    # So we read it, then "refill" it for the next handler.
    body_bytes = await request.body()
    # Refill the body stream so the endpoint can read it again
    request._receive =  lambda: {"type": "http.request", "body": body_bytes}
    
    user_prompt = "N/A"
    try:
        if body_bytes:
            data = json.loads(body_bytes)
            # Try to find 'query', 'prompt', or 'content'
            user_prompt = data.get("query") or data.get("prompt") or data.get("content") or "N/A"
    except:
        pass

    # 3. CRITICALITY CHECK
    # Define dangerous keywords list
    DANGEROUS_KEYWORDS = ["system prompt", "system show me", "default prompt", "ignore previous instructions"]
    is_critical = False
    
    if user_prompt and user_prompt != "N/A":
        lower_prompt = user_prompt.lower()
        if any(keyword in lower_prompt for keyword in DANGEROUS_KEYWORDS):
            is_critical = True

    # Process request
    try:
        response = await call_next(request)
    except Exception as e:
        # If an unhandled exception occurs (should be rare due to global handler), re-raise to let FastAPI handle it.
        # But for middleware logging, we might want to capture something.
        # However, FastAPI's exception handlers usually execute before middleware returns if they return a response.
        # If they raise, it bubbles up.
        raise e

    process_time = time.time() - start_time
    
    # Check if a security violation was flagged in the endpoint
    security_violation = getattr(request.state, "security_violation", None)
    
    log_data = {
        "event": "http_request",
        "client_ip": request.client.host,
        "method": request.method,
        "path": request.url.path,
        "status_code": response.status_code,
        "duration_seconds": round(process_time, 4),
        "prompt": user_prompt, 
        "is_critical": is_critical 
    }

    if security_violation:
        # MERGE security info into the log
        log_data["event"] = "security_violation"
        log_data["violation_type"] = security_violation.get("violation_type")
        log_data["input_sample"] = security_violation.get("input_sample")
        log_data["is_critical"] = True
        
        logger.warning(f"Security Blocked: {security_violation.get('violation_type')}", extra={"extra_data": log_data})
    
    elif is_critical:
        # Keyword match but no exception raised (e.g. might be allowed but flagged)
        logger.warning(f"CRITICAL PROMPT DETECTED: {user_prompt}", extra={"extra_data": log_data})
    else:
        logger.info("Request processed", extra={"extra_data": log_data})
    
    return response

# GLOBAL VARIABLES
## We load these once at startup so requests are fast
embedding_model = None
chroma_client = None
collection = None
groq_client = None
input_guard = None
output_guard = None

@app.on_event("startup")
async def startup_event():
   global embedding_model, chroma_client, collection, groq_client, input_guard, output_guard
   
   logger.info("Loading Models & Database...")
   if not API_KEY:
      raise ValueError("GROQ_API_KEY not found in .env file")
      
   embedding_model = SentenceTransformer(MODEL_NAME)
   chroma_client = chromadb.PersistentClient(path=DB_PATH)
   collection = chroma_client.get_collection(COLLECTION_NAME)
   groq_client = Groq(api_key=API_KEY)
   
   # Initialize Security Guards
   input_guard = InputGuard(log_events=True)
   output_guard = OutputGuard(log_events=True)
   logger.info("Input & Output Guards initialized.")
   logger.info("API is ready to accept requests.")

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
async def chat_endpoint(request: QueryRequest, raw_request: Request):
   try:
      user_query = request.query.strip()
      history = request.history

      if not user_query:
         raise HTTPException(status_code=400, detail="Query cannot be empty")
      
      # Security Layer: Input Validation
      try:
         input_guard.validate(user_query)
      except SecurityException as e:
         # Store violation details in state for the middleware to log ONCE
         raw_request.state.security_violation = {
             "violation_type": e.message,
             "input_sample": user_query[:50] 
         }
         
         # Customized User Message
         raise HTTPException(
            status_code=400, 
            detail=f"⚠️ Security Alert: Your request was blocked because it violates our safety policies. \nReason: {e.message}.\n\nPlease rephrase your query to focus on educational cyber security concepts."
         )
      
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
      
      # Security Layer: Output Sanitization
      sanitization_result = output_guard.sanitize_detailed(response_text)
      if sanitization_result.redactions_made > 0:
         print(f"[OUTPUT GUARD] Redacted {sanitization_result.redactions_made} sensitive items")
      response_text = sanitization_result.sanitized_text

      return QueryResponse(
         answer=response_text,
         sources=sources[:5] 
      )

   except HTTPException:
      # Re-raise HTTP exceptions as-is (including security violations)
      raise
   except Exception as e:
      logger.error(f"Internal Server Error: {e}")
      raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/logs")
async def get_logs():
    """Returns the last 100 log entries from the JSONL file."""
    log_file_path = os.path.join("logs", "events.jsonl")
    if not os.path.exists(log_file_path):
        return {"logs": []}
    
    logs = []
    try:
        with open(log_file_path, "r") as f:
            # Read all lines and take the last 100
            lines = f.readlines()
            last_lines = lines[-100:]
            
            for line in last_lines:
                try:
                    logs.append(json.loads(line))
                except json.JSONDecodeError:
                    continue # Skip broken lines
        
        # Calculate basic metrics
        total_requests = sum(1 for log in logs if log.get("event") == "http_request")
        security_events = sum(1 for log in logs if log.get("event") == "security_violation" or log.get("is_critical"))
        
        # Return reversed so newest are at top
        return {
            "logs": list(reversed(logs)), 
            "metrics": {
                "total_visible": len(logs),
                "http_requests": total_requests,
                "security_events": security_events
            }
        }
    except Exception as e:
        logger.error(f"Failed to read logs: {e}")
        return {"error": str(e)}