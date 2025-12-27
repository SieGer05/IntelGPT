import os
import sys
import chromadb
from sentence_transformers import SentenceTransformer
from groq import Groq
from dotenv import load_dotenv

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
         SECURE RAG SYSTEM - INTELLIGENT AGENT v1.0
   ========================================================
   {Colors.ENDC}"""
   print(banner)

# CONFIGURATION
load_dotenv()

API_KEY = os.environ.get("GROQ_API_KEY")
MODEL_NAME = "all-MiniLM-L6-v2"
DB_PATH = "./chroma_db"
COLLECTION_NAME = "mitre_attack"
GROQ_MODEL = "llama-3.3-70b-versatile"

def main():
   clear_screen()
   print_banner()

   # 1. API Key Verification
   if not API_KEY:
      print(f"{Colors.FAIL}[ERROR] GROQ_API_KEY not found in .env file!{Colors.ENDC}")
      print("Please ensure you have created a '.env' file with: GROQ_API_KEY=gsk_...")
      sys.exit(1)

   # 2. Resource Loading
   print(f"{Colors.CYAN}[INIT] Connecting to Groq API & ChromaDB...{Colors.ENDC}")
   try:
      embedding_model = SentenceTransformer(MODEL_NAME)
      chroma_client = chromadb.PersistentClient(path=DB_PATH)
      collection = chroma_client.get_collection(COLLECTION_NAME)
      groq_client = Groq(api_key=API_KEY)
      print(f"{Colors.GREEN}[READY] System Operational.{Colors.ENDC}\n")
   
   except Exception as e:
      print(f"{Colors.FAIL}[ERROR] Initialization failed: {e}{Colors.ENDC}")
      sys.exit(1)

   print(f"{Colors.BLUE}[INFO] Type 'exit' to quit.{Colors.ENDC}\n")

   # 3. Chat Loop
   while True:
      try:
         user_query = input(f"{Colors.BOLD}User > {Colors.ENDC}")
         if user_query.lower() in ['exit', 'quit', 'q']:
            break
         if not user_query.strip():
            continue

         # A. RETRIEVAL
         print(f"{Colors.CYAN}  -> Searching knowledge base...{Colors.ENDC}", end="\r")
         query_vector = embedding_model.encode([user_query]).tolist()
         results = collection.query(query_embeddings=query_vector, n_results=3)
         
         context_text = ""
         sources = []
         
         if results['documents'][0]:
            for i in range(len(results['documents'][0])):
               doc = results['documents'][0][i]
               meta = results['metadatas'][0][i]
               source_id = f"{meta['name']} (ID: {meta['external_id']})"
               sources.append(source_id)
               context_text += f"---\nSOURCE: {source_id}\nCONTENT: {doc}\n"
         else:
            print(f"{Colors.WARNING}  -> No relevant data found in MITRE database.{Colors.ENDC}")
            continue

         print(f"{Colors.GREEN}  -> Found {len(sources)} relevant documents.   {Colors.ENDC}")

         # B. GENERATION
         print(f"{Colors.CYAN}  -> Generating secure response...{Colors.ENDC}", end="\r")
         
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

         response = chat_completion.choices[0].message.content

         # C. DISPLAY
         print(f"\n{Colors.HEADER}--- AI Response ---{Colors.ENDC}")
         print(response)
         print(f"\n{Colors.BLUE}[Sources used: {', '.join(sources)}]{Colors.ENDC}\n")

      except Exception as e:
         print(f"\n{Colors.FAIL}[ERROR] An error occurred: {e}{Colors.ENDC}\n")

if __name__ == "__main__":
   main()