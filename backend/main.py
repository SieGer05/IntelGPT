import os
import json
import re
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import chromadb
from sentence_transformers import SentenceTransformer
from groq import Groq
from dotenv import load_dotenv

# Security Layer
from security import InputGuard, OutputGuard, SecurityException
from structured_logger import logger

# Hybrid Search (Vector + BM25)
from hybrid_search import HybridSearchEngine

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
hybrid_search_engine = None  # Hybrid Search (Vector + BM25)

@app.on_event("startup")
async def startup_event():
   global embedding_model, chroma_client, collection, groq_client, input_guard, output_guard, hybrid_search_engine
   
   logger.info("Loading Models & Database...")
   if not API_KEY:
      raise ValueError("GROQ_API_KEY not found in .env file")
      
   embedding_model = SentenceTransformer(MODEL_NAME)
   chroma_client = chromadb.PersistentClient(path=DB_PATH)
   collection = chroma_client.get_collection(COLLECTION_NAME)
   groq_client = Groq(api_key=API_KEY)
   
   # Initialize Hybrid Search Engine (Vector + BM25 + Reranking)
   hybrid_search_engine = HybridSearchEngine(
      collection=collection,
      embedding_model=embedding_model,
      vector_weight=0.5,  # Balanced weights
      bm25_weight=0.5,
      rerank_enabled=True,  # Enable cross-encoder reranking
      rerank_model="cross-encoder/ms-marco-MiniLM-L-6-v2",  # Fast & accurate model
      rerank_top_k=10  # Return top 10 after reranking
   )
   doc_count = hybrid_search_engine.build_bm25_index()
   logger.info(f"Hybrid Search Engine initialized with {doc_count} documents")
   
   # Log reranker status
   reranker_stats = hybrid_search_engine.get_reranker_stats()
   if reranker_stats.get("is_loaded"):
      logger.info(f"Cross-Encoder Reranker loaded: {reranker_stats.get('model_name')}")
   else:
      logger.warning("Cross-Encoder Reranker not loaded - will load on first search")
   
   # Initialize Security Guards
   input_guard = InputGuard(log_events=True)
   output_guard = OutputGuard(log_events=True)
   logger.info("Input & Output Guards initialized.")
   logger.info("API is ready to accept requests.")

# DATA MODELS 
class Message(BaseModel):
   role: str
   content: str

class DynamicFilters(BaseModel):
   """Dynamic filters for search refinement."""
   tactics: Optional[List[str]] = None  # e.g., ["initial-access", "execution"]
   platforms: Optional[List[str]] = None  # e.g., ["Windows", "Linux"]
   source: Optional[str] = None  # "MITRE ATT&CK" or "CISA KEV"
   chunk_type: Optional[str] = None  # "detection", "mitigation", etc.
   is_subtechnique: Optional[bool] = None

class QueryRequest(BaseModel):
   query: str
   history: List[Message] = []
   search_mode: str = "hybrid"  # "hybrid", "vector", or "bm25"
   filters: Optional[DynamicFilters] = None  # Dynamic filtering options

class QueryResponse(BaseModel):
   answer: str
   sources: list[str]
   search_info: Optional[dict] = None  # Optional search debugging info
   applied_filters: Optional[dict] = None  # Filters that were applied

class SearchRequest(BaseModel):
   query: str
   n_results: int = 5
   search_mode: str = "hybrid"  # "hybrid", "vector", or "bm25"
   filters: Optional[DynamicFilters] = None  # Dynamic filtering options

class SearchResponse(BaseModel):
   results: List[dict]
   search_mode: str
   vector_count: int
   bm25_count: int
   reranked: bool = False
   applied_filters: Optional[dict] = None

class FilterOptionsResponse(BaseModel):
   """Available filter options based on indexed data."""
   tactics: List[str]
   platforms: List[str]
   sources: List[str]
   chunk_types: List[str]


def build_chromadb_filter(filters: Optional[DynamicFilters]) -> Optional[dict]:
   """
   Build ChromaDB where filter from DynamicFilters.
   Supports AND logic with multiple conditions.
   """
   if not filters:
      return None
   
   conditions = []
   
   # Source filter (exact match)
   if filters.source:
      conditions.append({"source": filters.source})
   
   # Chunk type filter (exact match)
   if filters.chunk_type:
      conditions.append({"chunk_type": filters.chunk_type})
   
   # Subtechnique filter (boolean)
   if filters.is_subtechnique is not None:
      conditions.append({"is_subtechnique": filters.is_subtechnique})
   
   # Tactics filter (contains any - stored as comma-separated string)
   if filters.tactics and len(filters.tactics) > 0:
      # ChromaDB uses $contains for substring match in string fields
      # For multiple tactics, we create OR conditions
      if len(filters.tactics) == 1:
         conditions.append({"tactics": {"$contains": filters.tactics[0]}})
      else:
         tactic_conditions = [{"tactics": {"$contains": t}} for t in filters.tactics]
         conditions.append({"$or": tactic_conditions})
   
   # Platforms filter (contains any - stored as comma-separated string)
   if filters.platforms and len(filters.platforms) > 0:
      if len(filters.platforms) == 1:
         conditions.append({"platforms": {"$contains": filters.platforms[0]}})
      else:
         platform_conditions = [{"platforms": {"$contains": p}} for p in filters.platforms]
         conditions.append({"$or": platform_conditions})
   
   # Combine with AND logic
   if len(conditions) == 0:
      return None
   elif len(conditions) == 1:
      return conditions[0]
   else:
      return {"$and": conditions}


# FILTER OPTIONS ENDPOINT
@app.get("/api/filters", response_model=FilterOptionsResponse)
async def get_filter_options():
   """
   Returns all available filter options based on indexed data.
   This allows the frontend to dynamically populate filter dropdowns.
   """
   try:
      # Fetch all documents metadata
      all_docs = collection.get(include=["metadatas"])
      
      tactics_set = set()
      platforms_set = set()
      sources_set = set()
      chunk_types_set = set()
      
      for meta in all_docs.get("metadatas", []):
         # Parse tactics (comma-separated)
         if meta.get("tactics") and meta["tactics"] != "N/A":
            for tactic in meta["tactics"].split(", "):
               if tactic.strip():
                  tactics_set.add(tactic.strip())
         
         # Parse platforms (comma-separated)
         if meta.get("platforms") and meta["platforms"] != "N/A":
            for platform in meta["platforms"].split(", "):
               if platform.strip():
                  platforms_set.add(platform.strip())
         
         # Source
         if meta.get("source"):
            sources_set.add(meta["source"])
         
         # Chunk type
         if meta.get("chunk_type"):
            chunk_types_set.add(meta["chunk_type"])
      
      return FilterOptionsResponse(
         tactics=sorted(list(tactics_set)),
         platforms=sorted(list(platforms_set)),
         sources=sorted(list(sources_set)),
         chunk_types=sorted(list(chunk_types_set))
      )
   
   except Exception as e:
      logger.error(f"Failed to get filter options: {e}")
      raise HTTPException(status_code=500, detail=str(e))


# SEARCH ENDPOINT (for testing/debugging hybrid search)
@app.post("/search", response_model=SearchResponse)
async def search_endpoint(request: SearchRequest):
   """
   Direct search endpoint to test hybrid search.
   Returns raw search results with scoring details.
   Supports dynamic filtering by tactics, platforms, source, chunk_type.
   """
   try:
      # Build where filter from request filters
      where_filter = build_chromadb_filter(request.filters)
      applied_filters = None
      
      if where_filter:
         print(f"[SEARCH] Applying dynamic filters: {request.filters}")
         applied_filters = request.filters.model_dump(exclude_none=True) if request.filters else None
      
      results = hybrid_search_engine.search(
         query=request.query,
         n_results=request.n_results,
         search_mode=request.search_mode,
         where_filter=where_filter
      )
      
      formatted_results = []
      for i, doc_id in enumerate(results["ids"][0]):
         formatted_results.append({
            "rank": i + 1,
            "id": doc_id,
            "name": results["metadatas"][0][i].get("name", "Unknown"),
            "external_id": results["metadatas"][0][i].get("external_id", "N/A"),
            "tactics": results["metadatas"][0][i].get("tactics", "N/A"),
            "platforms": results["metadatas"][0][i].get("platforms", "N/A"),
            "source": results["metadatas"][0][i].get("source", "N/A"),
            "chunk_type": results["metadatas"][0][i].get("chunk_type", "N/A"),
            "hybrid_score": round(results["scores"]["hybrid"][i], 4),
            "vector_score": round(results["scores"]["vector"][i], 4),
            "bm25_score": round(results["scores"]["bm25"][i], 4),
            "rerank_score": round(results["scores"]["rerank"][i], 4) if results.get("reranked") else None,
            "excerpt": results["documents"][0][i][:200] + "..."
         })
      
      return SearchResponse(
         results=formatted_results,
         search_mode=results["search_mode"],
         vector_count=results["vector_results_count"],
         bm25_count=results["bm25_results_count"],
         reranked=results.get("reranked", False),
         applied_filters=applied_filters
      )
   except Exception as e:
      logger.error(f"Search error: {e}")
      raise HTTPException(status_code=500, detail=str(e))

# CHAT ENDPOINT
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
      applied_filters = None  # Initialize for both paths

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

         # --- MULTI-QUERY EXPANSION START ---
         # Generate semantic variants of the query for better coverage
         query_variants = [search_query]  # Always include original
         
         # Only expand if query is conceptual (not an ID lookup)
         cve_check = re.search(r"(CVE-\d{4}-\d{4,7})", search_query, re.IGNORECASE)
         mitre_check = re.search(r"(T\d{4}(?:\.\d{3})?)", search_query, re.IGNORECASE)
         
         if not cve_check and not mitre_check:
            print("[MULTI-QUERY] Generating query variants for better coverage...")
            
            expansion_prompt = f"""
            Generate 2 alternative search queries for the following cybersecurity question.
            Each variant should use different terminology or phrasing while preserving the original meaning.
            
            Original query: "{search_query}"
            
            Rules:
            - Use synonyms and related technical terms
            - Keep queries concise (under 15 words)
            - Focus on different aspects of the same concept
            - Output ONLY the 2 queries, one per line, no numbering or bullets
            """
            
            try:
               expansion_completion = groq_client.chat.completions.create(
                  messages=[{"role": "user", "content": expansion_prompt}],
                  model=GROQ_MODEL,
                  temperature=0.7,
                  max_tokens=150
               )
               
               expanded = expansion_completion.choices[0].message.content.strip()
               new_variants = [v.strip() for v in expanded.split('\n') if v.strip()][:2]
               query_variants.extend(new_variants)
               print(f"[MULTI-QUERY] Variants: {query_variants}")
            except Exception as e:
               print(f"[MULTI-QUERY] Expansion failed, using original query only: {e}")
         # --- MULTI-QUERY EXPANSION END ---

         print(f"[PATH] Technical Query -> Searching Database for: {search_query}")

         # --- SMART RETRIEVAL LOGIC START ---
         # Detect specific IDs (CVE or MITRE) to use deterministic filtering
         cve_match = re.search(r"(CVE-\d{4}-\d{4,7})", search_query, re.IGNORECASE)
         mitre_match = re.search(r"(T\d{4}(?:\.\d{3})?)", search_query, re.IGNORECASE)
         
         # Start with dynamic filters from request
         where_filter = build_chromadb_filter(request.filters)
         applied_filters = request.filters.model_dump(exclude_none=True) if request.filters else None
         
         if cve_match:
            target_id = cve_match.group(1).upper()
            print(f"[SMART SEARCH] Exact CVE detected: {target_id}")
            # Merge with existing filters using $and
            id_filter = {"external_id": target_id}
            if where_filter:
               where_filter = {"$and": [where_filter, id_filter]}
            else:
               where_filter = id_filter
             
         elif mitre_match:
            target_id = mitre_match.group(1).upper()
            print(f"[SMART SEARCH] Exact MITRE ID detected: {target_id}")
            # Merge with existing filters using $and
            id_filter = {"external_id": target_id}
            if where_filter:
               where_filter = {"$and": [where_filter, id_filter]}
            else:
               where_filter = id_filter
         
         # Log applied filters
         if applied_filters:
            print(f"[DYNAMIC FILTERS] Applying user filters: {applied_filters}")

         # --- HYBRID SEARCH (Vector + BM25) WITH MULTI-QUERY ---
         results = {'documents': [], 'metadatas': []}

         # Execute Hybrid Search
         if where_filter:
            # Case 1: Smart Filter Active (exact ID match) - use single query
            print(f"[HYBRID SEARCH] Using filter mode for exact ID match")
            results = hybrid_search_engine.search(
               query=search_query,
               n_results=5,
               where_filter=where_filter,
               search_mode="hybrid",
               min_score_threshold=0.1  # Apply threshold
            )
            # Fallback if filter returns nothing
            if not results['documents'] or not results['documents'][0]:
               print("[HYBRID SEARCH] ID not found, falling back to full hybrid search...")
               results = hybrid_search_engine.multi_query_search(
                  queries=query_variants,
                  n_results=10,
                  search_mode="hybrid",
                  min_score_threshold=0.05
               )
         else:
            # Case 2: Full Multi-Query Hybrid Search (Vector + BM25)
            print(f"[HYBRID SEARCH] Combining Vector + BM25 with {len(query_variants)} query variants")
            results = hybrid_search_engine.multi_query_search(
               queries=query_variants,
               n_results=10,
               search_mode="hybrid",
               min_score_threshold=0.05  # Filter low-quality results
            )
         
         # Log search performance
         print(f"[HYBRID SEARCH] Vector results: {results.get('vector_results_count', 0)}, BM25 results: {results.get('bm25_results_count', 0)}, Reranked: {results.get('reranked', False)}")
         if results.get('query_count'):
            print(f"[MULTI-QUERY] Used {results.get('query_count')} queries, found {results.get('unique_docs_found', 0)} unique docs")
         # --- END HYBRID SEARCH ---

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
         sources=sources[:5],
         applied_filters=applied_filters if intent == "technical" else None
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