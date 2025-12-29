import requests
import chromadb
from sentence_transformers import SentenceTransformer
from tqdm import tqdm
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
      SECURE RAG PIPELINE - DATA INGESTION ENGINE
   ========================================================
   {Colors.ENDC}"""
   print(banner)

def print_status(message, type="info"):
   if type == "info":
      print(f"{Colors.BLUE}[INFO]{Colors.ENDC} {message}")
   elif type == "process":
      print(f"{Colors.CYAN}[WORK]{Colors.ENDC} {message}")
   elif type == "success":
      print(f"{Colors.GREEN}[DONE]{Colors.ENDC} {message}")
   elif type == "error":
      print(f"{Colors.FAIL}[ERROR]{Colors.ENDC} {message}")

# CONFIGURATION
MODEL_NAME = "all-MiniLM-L6-v2"
MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DB_PATH = "./chroma_db" 
COLLECTION_NAME = "mitre_attack"
BATCH_SIZE = 100

def download_mitre_data():
   print_status("Contacting MITRE CTI servers...", "info")
   try:
      response = requests.get(MITRE_URL, timeout=30)
      if response.status_code != 200:
         raise RuntimeError(f"Server returned status code: {response.status_code}")
      print_status("MITRE Dataset downloaded successfully.", "success")
      return response.json()
   
   except Exception as e:
      print_status(f"Failed to download MITRE data: {e}", "error")
      sys.exit(1)

def download_cisa_data():
   print_status("Contacting CISA servers...", "info")
   try:
      response = requests.get(CISA_URL, timeout=30)
      if response.status_code != 200:
         raise RuntimeError(f"Server returned status code: {response.status_code}")
      print_status("CISA KEV Dataset downloaded successfully.", "success")
      return response.json()
   
   except Exception as e:
      print_status(f"Failed to download CISA data: {e}", "error")
      return None

def process_data(mitre_data):
   print_status("Parsing MITRE STIX objects...", "process")

   documents = []
   ids = []
   metadatas = []

   objects = mitre_data.get("objects", [])
   
   for obj in objects:
      if obj.get("type") != "attack-pattern" or obj.get("revoked", False):
         continue

      name = obj.get("name", "Unknown technique")
      description = obj.get("description", "No description available.")
      
      external_id = "UNKNOWN"
      for ref in obj.get("external_references", []):
         if ref.get("source_name") == "mitre-attack":
            external_id = ref.get("external_id", "UNKNOWN")
            break

      unique_id = f"{external_id}_{obj.get('id')}"

      tactics = [phase.get("phase_name") for phase in obj.get("kill_chain_phases", [])]
      platforms = obj.get("x_mitre_platforms", [])

      full_text = (
         f"MITRE ATT&CK Technique\n"
         f"ID: {external_id}\n"
         f"Name: {name}\n"
         f"Tactics: {', '.join(tactics) if tactics else 'N/A'}\n"
         f"Platforms: {', '.join(platforms) if platforms else 'N/A'}\n"
         f"Description: {description}"
      )

      documents.append(full_text)
      ids.append(unique_id)
      
      metadatas.append({
         "external_id": external_id,
         "name": name,
         "tactics": ", ".join(tactics) if tactics else "N/A",
         "platforms": ", ".join(platforms) if platforms else "N/A",
         "source": "MITRE ATT&CK"
      })

   print_status(f"Processed {len(documents)} MITRE techniques.", "success")
   return documents, ids, metadatas

def process_cisa_data(cisa_data):
   if not cisa_data:
      return [], [], []
      
   print_status("Parsing CISA KEV vulnerabilities...", "process")

   documents = []
   ids = []
   metadatas = []

   vulnerabilities = cisa_data.get("vulnerabilities", [])

   for vuln in vulnerabilities:
      cve_id = vuln.get("cveID")
      vendor = vuln.get("vendorProject")
      product = vuln.get("product")
      name = vuln.get("vulnerabilityName")
      description = vuln.get("shortDescription")
      
      unique_id = f"cve_{cve_id}"

      full_text = (
         f"CISA KEV Vulnerability\n"
         f"ID: {cve_id}\n"
         f"Name: {name}\n"
         f"Vendor: {vendor}\n"
         f"Product: {product}\n"
         f"Description: {description}"
      )

      documents.append(full_text)
      ids.append(unique_id)
      
      metadatas.append({
         "external_id": cve_id,
         "name": name,
         "tactics": "exploitation",
         "platforms": product,
         "source": "CISA KEV"
      })

   print_status(f"Processed {len(documents)} CISA vulnerabilities.", "success")
   return documents, ids, metadatas

def main():
   clear_screen()
   print_banner()

   mitre_data = download_mitre_data()
   cisa_data = download_cisa_data()

   mitre_docs, mitre_ids, mitre_metas = process_data(mitre_data)
   cisa_docs, cisa_ids, cisa_metas = process_cisa_data(cisa_data)

   documents = mitre_docs + cisa_docs
   ids = mitre_ids + cisa_ids
   metadatas = mitre_metas + cisa_metas

   print_status(f"Total Knowledge Base Size: {len(documents)} items.", "info")

   print_status(f"Loading Neural Network ({MODEL_NAME})...", "process")
   model = SentenceTransformer(MODEL_NAME)
   print_status("Model loaded in memory.", "success")

   print_status("Initializing Vector Database (ChromaDB)...", "process")
   client = chromadb.PersistentClient(path=DB_PATH)

   try:
      client.delete_collection(COLLECTION_NAME)
   except Exception:
      pass

   collection = client.create_collection(
      name=COLLECTION_NAME,
      metadata={"hnsw:space": "cosine"}
   )
   print_status(f"Collection '{COLLECTION_NAME}' created.", "success")

   print(f"\n{Colors.BOLD}Starting Vector Ingestion...{Colors.ENDC}")
   
   for i in tqdm(range(0, len(documents), BATCH_SIZE), 
      desc=f"{Colors.CYAN}Encoding & Storing{Colors.ENDC}", 
      ascii=" #", 
      colour="green"):
      
      batch_docs = documents[i:i + BATCH_SIZE]
      batch_ids = ids[i:i + BATCH_SIZE]
      batch_metas = metadatas[i:i + BATCH_SIZE]

      embeddings = model.encode(
         batch_docs,
         normalize_embeddings=True,
         show_progress_bar=False
      ).tolist()

      collection.add(
         documents=batch_docs,
         embeddings=embeddings,
         metadatas=batch_metas,
         ids=batch_ids
      )

   print(f"\n{Colors.HEADER}{Colors.BOLD}==========================================")
   print(f"SYSTEM READY. {len(documents)} Items Indexed (MITRE + CISA).")
   print(f"Database saved at: {DB_PATH}")
   print(f"=========================================={Colors.ENDC}\n")

if __name__ == "__main__":
   main()