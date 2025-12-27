import chromadb
from sentence_transformers import SentenceTransformer
import os
import sys

class Colors:
   HEADER = '\033[95m'
   BLUE = '\033[94m'
   CYAN = '\033[96m'
   GREEN = '\033[92m'
   WARNING = '\033[93m'
   FAIL = '\033[91m'
   ENDC = '\033[0m'
   BOLD = '\033[1m'
   UNDERLINE = '\033[4m'

def clear_screen():
   os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
   banner = f"""
   {Colors.HEADER}{Colors.BOLD}
   ========================================================
      SECURE RAG - SEARCH DIAGNOSTICS TOOL
   ========================================================
   {Colors.ENDC}"""
   print(banner)

# CONFIGURATION 
MODEL_NAME = "all-MiniLM-L6-v2"
DB_PATH = "./chroma_db"
COLLECTION_NAME = "mitre_attack"

def main():
   clear_screen()
   print_banner()

   # 1. Load Resources
   print(f"{Colors.CYAN}[WORK] Loading Embedding Model...{Colors.ENDC}")
   try:
      model = SentenceTransformer(MODEL_NAME)
   except Exception as e:
      print(f"{Colors.FAIL}[ERROR] Could not load model: {e}{Colors.ENDC}")
      sys.exit(1)

   print(f"{Colors.CYAN}[WORK] Connecting to Vector Database...{Colors.ENDC}")
   try:
      client = chromadb.PersistentClient(path=DB_PATH)
      collection = client.get_collection(COLLECTION_NAME)
      print(f"{Colors.GREEN}[DONE] Database connected. ({collection.count()} items){Colors.ENDC}")
   except Exception as e:
      print(f"{Colors.FAIL}[ERROR] Could not load database. Did you run ingest_data.py?{Colors.ENDC}")
      sys.exit(1)

   print(f"\n{Colors.BLUE}[INFO] Type 'exit' to quit.{Colors.ENDC}\n")

   # 2. Interactive Search Loop
   while True:
      try:
         query = input(f"{Colors.BOLD}Enter search query > {Colors.ENDC}")
         if query.lower() in ['exit', 'quit', 'q']:
            break
         
         if not query.strip():
            continue

         # Search
         query_vector = model.encode([query]).tolist()
         
         results = collection.query(
            query_embeddings=query_vector,
            n_results=3 
         )

         print(f"\n{Colors.HEADER}--- Top 3 Matches ---{Colors.ENDC}")
         
         if not results['documents'][0]:
            print(f"{Colors.WARNING}No results found.{Colors.ENDC}")
            continue

         for i in range(len(results['documents'][0])):
            doc = results['documents'][0][i]
            meta = results['metadatas'][0][i]
            doc_id = results['ids'][0][i]
            
            print(f"{Colors.GREEN}[Match #{i+1}]{Colors.ENDC} {Colors.BOLD}{meta['name']}{Colors.ENDC} (ID: {meta['external_id']})")
            print(f"{Colors.CYAN}Tactics:{Colors.ENDC} {meta['tactics']}")
            print(f"{Colors.CYAN}Platforms:{Colors.ENDC} {meta['platforms']}")
            
            # Print first 200 chars of description
            excerpt = doc.split("Description: ")[-1][:200].replace("\n", " ")
            print(f"{Colors.BLUE}Excerpt:{Colors.ENDC} {excerpt}...\n")
               
      except KeyboardInterrupt:
         break
   
   print(f"\n{Colors.GREEN}[DONE] Session closed.{Colors.ENDC}")

if __name__ == "__main__":
   main()

# Test 1 (Concept): "How to steal passwords from a web browser"
# Expected: Should find Credentials from Password Stores (T1555).

# Test 2 (Platform): "Attacks targeting Linux servers"
## Expected: Should find techniques listing Linux in platforms.

# Test 3 (Specific): "What is phishing?"
## Expected: Should find Phishing (T1566).