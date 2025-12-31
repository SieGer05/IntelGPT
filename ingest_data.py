import requests
import chromadb
from sentence_transformers import SentenceTransformer
from tqdm import tqdm
import os
import sys
import re
from typing import List, Dict, Tuple, Any

# ============================================
# SEMANTIC CHUNKING CONFIGURATION
# ============================================
CHUNK_SIZE = 512          # Target chunk size in characters
CHUNK_OVERLAP = 50        # Overlap between chunks for context continuity
MIN_CHUNK_SIZE = 100      # Minimum chunk size to avoid tiny fragments


class SemanticChunker:
    """
    Advanced semantic chunking for cybersecurity documents.
    Preserves context and creates meaningful chunks for better RAG retrieval.
    """
    
    def __init__(self, chunk_size: int = CHUNK_SIZE, overlap: int = CHUNK_OVERLAP, min_size: int = MIN_CHUNK_SIZE):
        self.chunk_size = chunk_size
        self.overlap = overlap
        self.min_size = min_size
        
        # Patterns for semantic boundaries in security documents
        self.section_patterns = [
            r'\n#{1,3}\s',           # Markdown headers
            r'\n\*\*[^*]+\*\*',      # Bold sections
            r'\n\d+\.\s',            # Numbered lists
            r'\n-\s',                # Bullet points
            r'\n\n',                 # Paragraph breaks
            r'(?<=[.!?])\s+(?=[A-Z])', # Sentence boundaries
        ]
    
    def _find_semantic_boundaries(self, text: str) -> List[int]:
        """Find natural breaking points in text based on semantic patterns."""
        boundaries = set([0, len(text)])
        
        for pattern in self.section_patterns:
            for match in re.finditer(pattern, text):
                boundaries.add(match.start())
        
        return sorted(boundaries)
    
    def _split_by_sentences(self, text: str) -> List[str]:
        """Split text into sentences while preserving structure."""
        # Handle common abbreviations to avoid false splits
        text = re.sub(r'(Mr|Mrs|Dr|Prof|Inc|Ltd|etc|vs|e\.g|i\.e)\.', r'\1<DOT>', text)
        sentences = re.split(r'(?<=[.!?])\s+', text)
        sentences = [s.replace('<DOT>', '.') for s in sentences]
        return [s.strip() for s in sentences if s.strip()]
    
    def chunk_document(self, text: str, metadata: Dict[str, Any]) -> List[Tuple[str, Dict[str, Any]]]:
        """
        Split a document into semantic chunks with enriched metadata.
        
        Returns:
            List of (chunk_text, chunk_metadata) tuples
        """
        if len(text) <= self.chunk_size:
            # Document is small enough, return as single chunk
            chunk_meta = metadata.copy()
            chunk_meta["chunk_index"] = 0
            chunk_meta["total_chunks"] = 1
            chunk_meta["chunk_type"] = "complete"
            return [(text, chunk_meta)]
        
        chunks = []
        boundaries = self._find_semantic_boundaries(text)
        
        current_chunk = ""
        current_start = 0
        chunk_index = 0
        
        for i, boundary in enumerate(boundaries[1:], 1):
            segment = text[boundaries[i-1]:boundary]
            
            # Check if adding this segment exceeds chunk size
            if len(current_chunk) + len(segment) > self.chunk_size:
                if len(current_chunk) >= self.min_size:
                    # Save current chunk
                    chunk_meta = metadata.copy()
                    chunk_meta["chunk_index"] = chunk_index
                    chunk_meta["chunk_type"] = self._identify_chunk_type(current_chunk)
                    chunk_meta["char_start"] = current_start
                    chunk_meta["char_end"] = boundaries[i-1]
                    chunks.append((current_chunk.strip(), chunk_meta))
                    chunk_index += 1
                    
                    # Start new chunk with overlap
                    overlap_text = current_chunk[-self.overlap:] if len(current_chunk) > self.overlap else ""
                    current_chunk = overlap_text + segment
                    current_start = boundaries[i-1] - len(overlap_text)
                else:
                    current_chunk += segment
            else:
                current_chunk += segment
        
        # Don't forget the last chunk
        if current_chunk.strip():
            chunk_meta = metadata.copy()
            chunk_meta["chunk_index"] = chunk_index
            chunk_meta["chunk_type"] = self._identify_chunk_type(current_chunk)
            chunk_meta["char_start"] = current_start
            chunk_meta["char_end"] = len(text)
            chunks.append((current_chunk.strip(), chunk_meta))
        
        # Update total_chunks count
        total = len(chunks)
        for _, meta in chunks:
            meta["total_chunks"] = total
        
        return chunks
    
    def _identify_chunk_type(self, text: str) -> str:
        """Identify the type of content in a chunk for better retrieval."""
        text_lower = text.lower()
        
        if any(kw in text_lower for kw in ["detection", "detect", "monitor", "logging"]):
            return "detection"
        elif any(kw in text_lower for kw in ["mitigation", "prevent", "defense", "protect"]):
            return "mitigation"
        elif any(kw in text_lower for kw in ["procedure", "example", "has been used", "was used"]):
            return "procedure"
        elif any(kw in text_lower for kw in ["impact", "consequence", "result"]):
            return "impact"
        elif any(kw in text_lower for kw in ["cve-", "vulnerability", "exploit"]):
            return "vulnerability"
        else:
            return "description"


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

def process_data(mitre_data, chunker: SemanticChunker):
   """Process MITRE ATT&CK data with semantic chunking."""
   print_status("Parsing MITRE STIX objects with semantic chunking...", "process")

   documents = []
   ids = []
   metadatas = []
   total_techniques = 0

   objects = mitre_data.get("objects", [])
   
   for obj in objects:
      if obj.get("type") != "attack-pattern" or obj.get("revoked", False):
         continue

      total_techniques += 1
      name = obj.get("name", "Unknown technique")
      description = obj.get("description", "No description available.")
      
      external_id = "UNKNOWN"
      url = ""
      for ref in obj.get("external_references", []):
         if ref.get("source_name") == "mitre-attack":
            external_id = ref.get("external_id", "UNKNOWN")
            url = ref.get("url", "")
            break

      tactics = [phase.get("phase_name") for phase in obj.get("kill_chain_phases", [])]
      platforms = obj.get("x_mitre_platforms", [])
      
      # Build context header that will be included in each chunk
      context_header = (
         f"MITRE ATT&CK Technique: {name} ({external_id})\n"
         f"Tactics: {', '.join(tactics) if tactics else 'N/A'}\n"
         f"Platforms: {', '.join(platforms) if platforms else 'N/A'}\n"
         f"---\n"
      )

      # Full document for chunking
      full_text = context_header + description
      
      # Extract additional context from MITRE data
      detection = obj.get("x_mitre_detection", "")
      if detection:
         full_text += f"\n\n### Detection\n{detection}"
      
      # Base metadata for this technique
      base_metadata = {
         "external_id": external_id,
         "name": name,
         "tactics": ", ".join(tactics) if tactics else "N/A",
         "platforms": ", ".join(platforms) if platforms else "N/A",
         "source": "MITRE ATT&CK",
         "url": url,
         "is_subtechnique": "." in external_id
      }

      # Apply semantic chunking
      chunks = chunker.chunk_document(full_text, base_metadata)
      
      for chunk_text, chunk_meta in chunks:
         unique_id = f"{external_id}_{obj.get('id')}_chunk{chunk_meta['chunk_index']}"
         documents.append(chunk_text)
         ids.append(unique_id)
         metadatas.append(chunk_meta)

   print_status(f"Processed {total_techniques} MITRE techniques into {len(documents)} semantic chunks.", "success")
   return documents, ids, metadatas

def process_cisa_data(cisa_data, chunker: SemanticChunker):
   """Process CISA KEV data with semantic chunking."""
   if not cisa_data:
      return [], [], []
      
   print_status("Parsing CISA KEV vulnerabilities with semantic chunking...", "process")

   documents = []
   ids = []
   metadatas = []
   total_vulns = 0

   vulnerabilities = cisa_data.get("vulnerabilities", [])

   for vuln in vulnerabilities:
      total_vulns += 1
      cve_id = vuln.get("cveID", "UNKNOWN")
      vendor = vuln.get("vendorProject", "Unknown")
      product = vuln.get("product", "Unknown")
      name = vuln.get("vulnerabilityName", "Unknown vulnerability")
      description = vuln.get("shortDescription", "No description available.")
      date_added = vuln.get("dateAdded", "")
      due_date = vuln.get("dueDate", "")
      known_ransomware = vuln.get("knownRansomwareCampaignUse", "Unknown")
      required_action = vuln.get("requiredAction", "")
      notes = vuln.get("notes", "")
      
      # Build comprehensive document
      context_header = (
         f"CISA Known Exploited Vulnerability: {name}\n"
         f"CVE ID: {cve_id}\n"
         f"Vendor: {vendor} | Product: {product}\n"
         f"Date Added to KEV: {date_added}\n"
         f"Ransomware Use: {known_ransomware}\n"
         f"---\n"
      )
      
      full_text = context_header + f"Description: {description}"
      
      if required_action:
         full_text += f"\n\n### Required Action\n{required_action}"
      
      if notes:
         full_text += f"\n\n### Notes\n{notes}"
      
      # Base metadata
      base_metadata = {
         "external_id": cve_id,
         "name": name,
         "vendor": vendor,
         "product": product,
         "tactics": "exploitation",
         "platforms": product,
         "source": "CISA KEV",
         "date_added": date_added,
         "due_date": due_date,
         "ransomware_use": known_ransomware
      }

      # Apply semantic chunking
      chunks = chunker.chunk_document(full_text, base_metadata)
      
      for chunk_text, chunk_meta in chunks:
         unique_id = f"cve_{cve_id}_chunk{chunk_meta['chunk_index']}"
         documents.append(chunk_text)
         ids.append(unique_id)
         metadatas.append(chunk_meta)

   print_status(f"Processed {total_vulns} CISA vulnerabilities into {len(documents)} semantic chunks.", "success")
   return documents, ids, metadatas

def main():
   clear_screen()
   print_banner()

   # Initialize semantic chunker
   print_status("Initializing Semantic Chunker...", "process")
   chunker = SemanticChunker(
      chunk_size=CHUNK_SIZE,
      overlap=CHUNK_OVERLAP,
      min_size=MIN_CHUNK_SIZE
   )
   print_status(f"Chunker configured: size={CHUNK_SIZE}, overlap={CHUNK_OVERLAP}", "success")

   mitre_data = download_mitre_data()
   cisa_data = download_cisa_data()

   mitre_docs, mitre_ids, mitre_metas = process_data(mitre_data, chunker)
   cisa_docs, cisa_ids, cisa_metas = process_cisa_data(cisa_data, chunker)

   documents = mitre_docs + cisa_docs
   ids = mitre_ids + cisa_ids
   metadatas = mitre_metas + cisa_metas

   print_status(f"Total Knowledge Base Size: {len(documents)} semantic chunks.", "info")

   # Display chunking statistics
   chunk_types = {}
   for meta in metadatas:
      ct = meta.get("chunk_type", "unknown")
      chunk_types[ct] = chunk_types.get(ct, 0) + 1
   
   print_status("Chunk distribution by type:", "info")
   for ct, count in sorted(chunk_types.items(), key=lambda x: -x[1]):
      print(f"   {Colors.CYAN}→{Colors.ENDC} {ct}: {count}")

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