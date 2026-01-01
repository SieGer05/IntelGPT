"""
RAG CLI Application - Modernized Version
=========================================
Interactive command-line interface for the Secure RAG System.
Now uses Hybrid Search (Vector + BM25), Reranking, and Multi-Query Expansion.
"""

import os
import sys
import re
import chromadb
from sentence_transformers import SentenceTransformer
from groq import Groq
from dotenv import load_dotenv

# Add backend to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

from hybrid_search import HybridSearchEngine
from reranker import CrossEncoderReranker


class Colors:
   HEADER = '\033[95m'
   BLUE = '\033[94m'
   CYAN = '\033[96m'
   GREEN = '\033[92m'
   WARNING = '\033[93m'
   FAIL = '\033[91m'
   ENDC = '\033[0m'
   BOLD = '\033[1m'


def clear_screen():
   os.system('cls' if os.name == 'nt' else 'clear')


def print_banner():
   banner = f"""
   {Colors.HEADER}{Colors.BOLD}
   ========================================================
      SECURE RAG SYSTEM - INTELLIGENT AGENT v2.0
            Hybrid Search + Reranking Enabled
   ========================================================
   {Colors.ENDC}"""
   print(banner)


def print_status(message, status_type="info"):
   icons = {
      "info": f"{Colors.BLUE}[INFO]{Colors.ENDC}",
      "success": f"{Colors.GREEN}[✓]{Colors.ENDC}",
      "warning": f"{Colors.WARNING}[!]{Colors.ENDC}",
      "error": f"{Colors.FAIL}[✗]{Colors.ENDC}",
      "search": f"{Colors.CYAN}[SEARCH]{Colors.ENDC}",
   }
   print(f"{icons.get(status_type, icons['info'])} {message}")


# CONFIGURATION
load_dotenv()

API_KEY = os.environ.get("GROQ_API_KEY")
MODEL_NAME = "all-MiniLM-L6-v2"
DB_PATH = "./chroma_db"
COLLECTION_NAME = "mitre_attack"
GROQ_MODEL = "llama-3.3-70b-versatile"


def expand_query(groq_client, query: str) -> list:
   """Generate query variants for better semantic coverage."""
   expansion_prompt = f"""
   Generate 2 alternative search queries for the following cybersecurity question.
   Each variant should use different terminology while preserving meaning.
   
   Original: "{query}"
   
   Rules:
   - Use synonyms and related technical terms
   - Keep queries concise
   - Output ONLY the 2 queries, one per line
   """
   
   try:
      completion = groq_client.chat.completions.create(
         messages=[{"role": "user", "content": expansion_prompt}],
         model=GROQ_MODEL,
         temperature=0.7,
         max_tokens=100
      )
      variants = [v.strip() for v in completion.choices[0].message.content.strip().split('\n') if v.strip()]
      return [query] + variants[:2]
   except Exception:
      return [query]


def main():
   clear_screen()
   print_banner()

   # 1. API Key Verification
   if not API_KEY:
      print(f"{Colors.FAIL}[ERROR] GROQ_API_KEY not found in .env file!{Colors.ENDC}")
      print("Please ensure you have created a '.env' file with: GROQ_API_KEY=gsk_...")
      sys.exit(1)

   # 2. Resource Loading
   print_status("Initializing Secure RAG System...", "info")
   
   try:
      print_status("Loading embedding model...", "info")
      embedding_model = SentenceTransformer(MODEL_NAME)
      
      print_status("Connecting to ChromaDB...", "info")
      chroma_client = chromadb.PersistentClient(path=DB_PATH)
      collection = chroma_client.get_collection(COLLECTION_NAME)
      
      print_status("Initializing Groq LLM client...", "info")
      groq_client = Groq(api_key=API_KEY)
      
      # Initialize Hybrid Search Engine with Reranking
      print_status("Building Hybrid Search Engine (Vector + BM25)...", "info")
      hybrid_engine = HybridSearchEngine(
         collection=collection,
         embedding_model=embedding_model,
         vector_weight=0.5,
         bm25_weight=0.5,
         rerank_enabled=True,
         rerank_model="cross-encoder/ms-marco-MiniLM-L-6-v2",
         rerank_top_k=5
      )
      
      doc_count = hybrid_engine.build_bm25_index()
      print_status(f"Indexed {doc_count} documents for BM25 search", "success")
      
      reranker_stats = hybrid_engine.get_reranker_stats()
      if reranker_stats.get("is_loaded"):
         print_status(f"Cross-Encoder Reranker loaded: {reranker_stats.get('model_name')}", "success")
      
      print_status("System Operational!", "success")
      
   except Exception as e:
      print_status(f"Initialization failed: {e}", "error")
      sys.exit(1)

   print(f"\n{Colors.BLUE}Commands: 'exit' to quit, 'stats' for search stats, 'explain <query>' for search breakdown{Colors.ENDC}\n")
   
   # Conversation history for context
   history = []

   # 3. Chat Loop
   while True:
      try:
         user_query = input(f"{Colors.BOLD}You > {Colors.ENDC}").strip()
         
         if not user_query:
            continue
         
         if user_query.lower() in ['exit', 'quit', 'q']:
            print_status("Goodbye!", "info")
            break
         
         # Special command: stats
         if user_query.lower() == 'stats':
            stats = hybrid_engine.get_reranker_stats()
            print(f"\n{Colors.CYAN}=== Search Engine Stats ==={Colors.ENDC}")
            print(f"  Reranker Enabled: {stats.get('enabled', False)}")
            print(f"  Reranker Loaded: {stats.get('is_loaded', False)}")
            print(f"  Model: {stats.get('model_name', 'N/A')}")
            print(f"  Load Time: {stats.get('load_time_seconds', 0):.2f}s\n")
            continue
         
         # Special command: explain
         if user_query.lower().startswith('explain '):
            query_to_explain = user_query[8:].strip()
            if query_to_explain:
               print(f"\n{Colors.CYAN}{hybrid_engine.explain_search(query_to_explain)}{Colors.ENDC}\n")
            continue
         
         # --- QUERY CONTEXTUALIZATION (Resolve pronouns using history) ---
         search_query = user_query
         if history:
            print_status("Contextualizing query based on conversation history...", "info")
            history_block = "\n".join([f"{msg['role']}: {msg['content']}" for msg in history[-6:]])
            
            rewrite_prompt = f"""
            Analyze the user's query and the conversation history to resolve any references.
            
            RULES:
            1. If the query contains pronouns like "it", "this", "that", "its", "they", "them" referring to something in history, replace them with the specific terms.
            2. If the query asks about "sub-techniques", "related techniques", "examples", "more details" - ADD the topic from history.
            3. If the query is a NEW TOPIC unrelated to history, return the query AS-IS.
            4. "What is X?" where X is a clear NEW concept is a NEW TOPIC - don't add history context.
            
            History:
            {history_block}
            
            User Query: {user_query}
            
            Output ONLY the rewritten query string (or original if it's a new topic). Nothing else.
            """
            
            try:
               rewrite_completion = groq_client.chat.completions.create(
                  messages=[{"role": "user", "content": rewrite_prompt}],
                  model=GROQ_MODEL,
                  temperature=0.1
               )
               search_query = rewrite_completion.choices[0].message.content.strip()
               if search_query != user_query:
                  print_status(f"Rewritten: '{user_query}' -> '{search_query}'", "info")
            except Exception as e:
               print_status(f"Query rewrite failed, using original: {e}", "warning")
         
         # Detect specific IDs for exact matching
         cve_match = re.search(r"(CVE-\d{4}-\d{4,7})", search_query, re.IGNORECASE)
         mitre_match = re.search(r"(T\d{4}(?:\.\d{3})?)", search_query, re.IGNORECASE)
         
         where_filter = None
         if cve_match:
            target_id = cve_match.group(1).upper()
            where_filter = {"external_id": target_id}
            print_status(f"Exact CVE lookup: {target_id}", "search")
         elif mitre_match:
            target_id = mitre_match.group(1).upper()
            where_filter = {"external_id": target_id}
            print_status(f"Exact MITRE ID lookup: {target_id}", "search")
         
         # A. RETRIEVAL with Hybrid Search
         if where_filter:
            # Exact ID search
            print_status("Searching with exact ID filter...", "search")
            results = hybrid_engine.search(
               query=search_query,
               n_results=5,
               where_filter=where_filter,
               search_mode="hybrid",
               min_score_threshold=0.1
            )
            
            # Fallback if not found
            if not results['documents'] or not results['documents'][0]:
               print_status("ID not found, expanding search...", "warning")
               query_variants = expand_query(groq_client, search_query)
               results = hybrid_engine.multi_query_search(
                  queries=query_variants,
                  n_results=5,
                  search_mode="hybrid",
                  min_score_threshold=0.05
               )
         else:
            # Multi-query hybrid search
            print_status("Generating query variants...", "search")
            query_variants = expand_query(groq_client, search_query)
            print_status(f"Searching with {len(query_variants)} query variants...", "search")
            
            results = hybrid_engine.multi_query_search(
               queries=query_variants,
               n_results=5,
               search_mode="hybrid",
               min_score_threshold=0.05
            )
         
         context_text = ""
         sources = []
         
         if results['documents'] and results['documents'][0]:
            print_status(f"Found {len(results['documents'][0])} relevant documents (Reranked: {results.get('reranked', False)})", "success")
            
            for i in range(len(results['documents'][0])):
               doc = results['documents'][0][i]
               meta = results['metadatas'][0][i]
               scores = results['scores']
               
               source_id = f"{meta.get('name', 'Unknown')} ({meta.get('external_id', 'N/A')})"
               if source_id not in sources:
                  sources.append(source_id)
               
               context_text += f"---\nSOURCE: {source_id}\n"
               context_text += f"SCORES: hybrid={scores['hybrid'][i]:.4f}, vector={scores['vector'][i]:.4f}, bm25={scores['bm25'][i]:.4f}"
               if results.get('reranked') and scores['rerank'][i]:
                  context_text += f", rerank={scores['rerank'][i]:.4f}"
               context_text += f"\nCONTENT: {doc}\n"
         else:
            print_status("No relevant data found in knowledge base.", "warning")
            continue

         # B. GENERATION with context
         print_status("Generating response...", "info")
         
         system_prompt = f"""
         You are a Cyber Threat Intelligence Expert.
         Use ONLY the following context to answer the user's question.
         If the answer is not in the context, say "I don't have enough information in my database."
         
         CONTEXT:
         {context_text}
         
         Keep the answer technical, concise, and structured.
         Always cite the sources you used.
         """
         
         # Build messages with history
         messages = [{"role": "system", "content": system_prompt}]
         for msg in history[-6:]:  # Sliding window
            messages.append(msg)
         messages.append({"role": "user", "content": user_query})

         chat_completion = groq_client.chat.completions.create(
            messages=messages,
            model=GROQ_MODEL,
            temperature=0.0,
         )

         response = chat_completion.choices[0].message.content
         
         # Update history
         history.append({"role": "user", "content": user_query})
         history.append({"role": "assistant", "content": response})

         # C. DISPLAY
         print(f"\n{Colors.HEADER}{'='*60}{Colors.ENDC}")
         print(f"{Colors.GREEN}{Colors.BOLD}Assistant:{Colors.ENDC}")
         print(response)
         print(f"\n{Colors.BLUE}[Sources: {', '.join(sources[:3])}]{Colors.ENDC}")
         print(f"{Colors.HEADER}{'='*60}{Colors.ENDC}\n")

      except KeyboardInterrupt:
         print(f"\n{Colors.WARNING}Interrupted. Type 'exit' to quit.{Colors.ENDC}")
      except Exception as e:
         print(f"\n{Colors.FAIL}[ERROR] {e}{Colors.ENDC}\n")


if __name__ == "__main__":
   main()