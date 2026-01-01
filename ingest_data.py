import requests
import chromadb
from sentence_transformers import SentenceTransformer
from tqdm import tqdm
import os
import sys
import re
import time
import argparse
from typing import List, Dict, Tuple, Any
from datetime import datetime, timedelta

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
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DB_PATH = "./chroma_db" 
COLLECTION_NAME = "mitre_attack"
BATCH_SIZE = 100

# NVD Configuration
NVD_RESULTS_PER_PAGE = 2000  # Max allowed by NVD API
NVD_RATE_LIMIT_DELAY = 6     # Seconds between requests (NVD limit: 5 req/30sec without API key)
NVD_MIN_CVSS_SCORE = 4.0     # Only import CVE with CVSS >= this score (reduces noise)

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


def build_cve_to_mitre_mapping(mitre_data: Dict) -> Dict[str, List[Dict]]:
   """
   Extract CVE references from MITRE ATT&CK data to build CVE→Technique mapping.
   
   MITRE techniques often reference CVE in their descriptions when the technique
   exploits a specific vulnerability.
   
   Returns:
      Dict mapping CVE ID to list of {technique_id, technique_name, context}
   """
   print_status("Building CVE→MITRE technique mapping...", "process")
   
   cve_pattern = re.compile(r'(CVE-\d{4}-\d{4,7})', re.IGNORECASE)
   cve_to_techniques = {}
   
   objects = mitre_data.get("objects", [])
   
   for obj in objects:
      if obj.get("type") != "attack-pattern" or obj.get("revoked", False):
         continue
      
      # Get technique info
      name = obj.get("name", "Unknown")
      description = obj.get("description", "")
      
      external_id = "UNKNOWN"
      for ref in obj.get("external_references", []):
         if ref.get("source_name") == "mitre-attack":
            external_id = ref.get("external_id", "UNKNOWN")
            break
      
      # Find all CVE references in description
      cve_matches = cve_pattern.findall(description)
      
      for cve_id in cve_matches:
         cve_id = cve_id.upper()
         
         # Extract context around the CVE mention (50 chars before and after)
         for match in re.finditer(re.escape(cve_id), description, re.IGNORECASE):
            start = max(0, match.start() - 100)
            end = min(len(description), match.end() + 100)
            context = description[start:end].strip()
            
            if cve_id not in cve_to_techniques:
               cve_to_techniques[cve_id] = []
            
            # Avoid duplicates
            existing = [t for t in cve_to_techniques[cve_id] if t["technique_id"] == external_id]
            if not existing:
               cve_to_techniques[cve_id].append({
                  "technique_id": external_id,
                  "technique_name": name,
                  "context": context
               })
            break  # Only need one context per technique
   
   # Also check external references for CVE links
   for obj in objects:
      if obj.get("type") != "attack-pattern" or obj.get("revoked", False):
         continue
      
      name = obj.get("name", "Unknown")
      external_id = "UNKNOWN"
      
      for ref in obj.get("external_references", []):
         if ref.get("source_name") == "mitre-attack":
            external_id = ref.get("external_id", "UNKNOWN")
         
         # Check if any reference URL contains a CVE
         url = ref.get("url", "")
         desc = ref.get("description", "")
         
         for text in [url, desc]:
            cve_matches = cve_pattern.findall(text)
            for cve_id in cve_matches:
               cve_id = cve_id.upper()
               if cve_id not in cve_to_techniques:
                  cve_to_techniques[cve_id] = []
               
               existing = [t for t in cve_to_techniques[cve_id] if t["technique_id"] == external_id]
               if not existing:
                  cve_to_techniques[cve_id].append({
                     "technique_id": external_id,
                     "technique_name": name,
                     "context": f"Referenced in {ref.get('source_name', 'external source')}"
                  })
   
   print_status(f"Found {len(cve_to_techniques)} CVE with MITRE technique mappings", "success")
   return cve_to_techniques


def download_nvd_data(api_key: str = None, days_back: int = None, min_cvss: float = NVD_MIN_CVSS_SCORE):
   """
   Download CVE data from NVD (National Vulnerability Database).
   
   Args:
      api_key: Optional NVD API key for faster rate limits (50 req/30sec vs 5 req/30sec)
      days_back: Only fetch CVE modified in last N days (None = all CVE)
      min_cvss: Minimum CVSS score to include (filters out low-severity CVE)
   
   Returns:
      List of CVE vulnerability dictionaries
   """
   print_status("Contacting NVD (National Vulnerability Database)...", "info")
   print_status(f"Filter: CVSS >= {min_cvss}" + (f", Last {days_back} days" if days_back else ", All time"), "info")
   
   all_vulnerabilities = []
   start_index = 0
   total_results = None
   
   # Build base parameters
   params = {
      "resultsPerPage": NVD_RESULTS_PER_PAGE,
   }
   
   # Add date filter if specified
   if days_back:
      end_date = datetime.utcnow()
      start_date = end_date - timedelta(days=days_back)
      params["lastModStartDate"] = start_date.strftime("%Y-%m-%dT00:00:00.000")
      params["lastModEndDate"] = end_date.strftime("%Y-%m-%dT23:59:59.999")
   
   # Add CVSS filter (v3 severity)
   if min_cvss >= 9.0:
      params["cvssV3Severity"] = "CRITICAL"
   elif min_cvss >= 7.0:
      params["cvssV3Severity"] = "HIGH"
   elif min_cvss >= 4.0:
      params["cvssV3Severity"] = "MEDIUM"
   
   # Headers
   headers = {"Accept": "application/json"}
   if api_key:
      headers["apiKey"] = api_key
      delay = 0.6  # With API key: 50 requests per 30 seconds
   else:
      delay = NVD_RATE_LIMIT_DELAY  # Without API key: 5 requests per 30 seconds
   
   try:
      # First request to get total count
      params["startIndex"] = start_index
      response = requests.get(NVD_API_URL, params=params, headers=headers, timeout=60)
      
      if response.status_code == 403:
         print_status("NVD API rate limited. Waiting 30 seconds...", "warning")
         time.sleep(30)
         response = requests.get(NVD_API_URL, params=params, headers=headers, timeout=60)
      
      if response.status_code != 200:
         raise RuntimeError(f"NVD API returned status code: {response.status_code}")
      
      data = response.json()
      total_results = data.get("totalResults", 0)
      
      print_status(f"NVD reports {total_results:,} CVE matching criteria", "info")
      
      if total_results == 0:
         return []
      
      # Process first batch
      vulnerabilities = data.get("vulnerabilities", [])
      all_vulnerabilities.extend(vulnerabilities)
      start_index += len(vulnerabilities)
      
      # Progress bar for remaining pages
      with tqdm(total=total_results, initial=len(vulnerabilities), 
                desc=f"{Colors.CYAN}Downloading NVD{Colors.ENDC}", 
                ascii=" #", colour="cyan") as pbar:
         
         while start_index < total_results:
            time.sleep(delay)  # Rate limiting
            
            params["startIndex"] = start_index
            response = requests.get(NVD_API_URL, params=params, headers=headers, timeout=60)
            
            if response.status_code == 403:
               print_status("\nRate limited, waiting 30 seconds...", "warning")
               time.sleep(30)
               continue
            
            if response.status_code != 200:
               print_status(f"\nError on page {start_index}: {response.status_code}", "warning")
               break
            
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            
            if not vulnerabilities:
               break
            
            all_vulnerabilities.extend(vulnerabilities)
            start_index += len(vulnerabilities)
            pbar.update(len(vulnerabilities))
      
      print_status(f"Downloaded {len(all_vulnerabilities):,} CVE from NVD", "success")
      return all_vulnerabilities
   
   except Exception as e:
      print_status(f"Failed to download NVD data: {e}", "error")
      return []


def process_nvd_data(nvd_data: List[Dict], chunker: SemanticChunker, existing_cve_ids: set = None, cve_to_mitre: Dict[str, List[Dict]] = None):
   """
   Process NVD CVE data with semantic chunking and MITRE enrichment.
   
   Args:
      nvd_data: List of NVD vulnerability objects
      chunker: SemanticChunker instance
      existing_cve_ids: Set of CVE IDs already in database (to avoid duplicates with CISA)
      cve_to_mitre: Dict mapping CVE IDs to list of related MITRE techniques
   
   Returns:
      Tuple of (documents, ids, metadatas)
   """
   if not nvd_data:
      return [], [], []
   
   if existing_cve_ids is None:
      existing_cve_ids = set()
   
   if cve_to_mitre is None:
      cve_to_mitre = {}
   
   print_status(f"Processing {len(nvd_data):,} NVD vulnerabilities with semantic chunking...", "process")
   
   documents = []
   ids = []
   metadatas = []
   skipped = 0
   processed = 0
   enriched_count = 0
   
   for vuln_wrapper in tqdm(nvd_data, desc=f"{Colors.CYAN}Processing NVD{Colors.ENDC}", 
                            ascii=" #", colour="green"):
      try:
         cve = vuln_wrapper.get("cve", {})
         cve_id = cve.get("id", "UNKNOWN")
         
         # Skip if already in CISA KEV
         if cve_id in existing_cve_ids:
            skipped += 1
            continue
         
         # Extract CVSS scores
         metrics = cve.get("metrics", {})
         cvss_v3 = None
         cvss_v2 = None
         severity = "UNKNOWN"
         
         # Try CVSSv3.1 first, then v3.0, then v2
         if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
            cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
            cvss_v3 = cvss_data.get("baseScore", 0)
            severity = cvss_data.get("baseSeverity", "UNKNOWN")
         elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
            cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
            cvss_v3 = cvss_data.get("baseScore", 0)
            severity = cvss_data.get("baseSeverity", "UNKNOWN")
         elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
            cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
            cvss_v2 = cvss_data.get("baseScore", 0)
            severity = "MEDIUM" if cvss_v2 and cvss_v2 >= 4 else "LOW"
         
         # Get descriptions (prefer English)
         descriptions = cve.get("descriptions", [])
         description = "No description available."
         for desc in descriptions:
            if desc.get("lang") == "en":
               description = desc.get("value", description)
               break
         
         # Get affected products (CPE)
         configurations = cve.get("configurations", [])
         affected_products = []
         vendors = set()
         
         for config in configurations:
            for node in config.get("nodes", []):
               for cpe_match in node.get("cpeMatch", []):
                  cpe = cpe_match.get("criteria", "")
                  # Parse CPE: cpe:2.3:a:vendor:product:version:...
                  parts = cpe.split(":")
                  if len(parts) >= 5:
                     vendors.add(parts[3])
                     affected_products.append(f"{parts[3]} {parts[4]}")
         
         # Get references
         references = cve.get("references", [])
         ref_urls = [ref.get("url", "") for ref in references[:3]]  # First 3 refs
         
         # Get weaknesses (CWE)
         weaknesses = cve.get("weaknesses", [])
         cwe_ids = []
         for weakness in weaknesses:
            for desc in weakness.get("description", []):
               if desc.get("lang") == "en":
                  cwe_ids.append(desc.get("value", ""))
         
         # Check for MITRE technique mapping
         mitre_techniques = cve_to_mitre.get(cve_id.upper(), [])
         mitre_ids = [t["technique_id"] for t in mitre_techniques]
         mitre_names = [t["technique_name"] for t in mitre_techniques]
         
         if mitre_techniques:
            enriched_count += 1
         
         # Build comprehensive document
         context_header = (
            f"NVD Vulnerability: {cve_id}\n"
            f"Severity: {severity} (CVSS: {cvss_v3 or cvss_v2 or 'N/A'})\n"
            f"Vendors: {', '.join(list(vendors)[:5]) if vendors else 'N/A'}\n"
            f"CWE: {', '.join(cwe_ids[:3]) if cwe_ids else 'N/A'}\n"
         )
         
         # Add MITRE mapping if available
         if mitre_techniques:
            mitre_list = ', '.join([f"{t['technique_id']} ({t['technique_name']})" for t in mitre_techniques])
            context_header += f"Related MITRE Techniques: {mitre_list}\n"
         
         context_header += "---\n"
         
         full_text = context_header + f"Description: {description}"
         
         if affected_products:
            full_text += f"\n\n### Affected Products\n" + "\n".join(affected_products[:10])
         
         if ref_urls:
            full_text += f"\n\n### References\n" + "\n".join(ref_urls)
         
         # Add MITRE context if available
         if mitre_techniques:
            full_text += f"\n\n### Related MITRE ATT&CK Techniques\n"
            for tech in mitre_techniques:
               full_text += f"- {tech['technique_id']} ({tech['technique_name']}): {tech['context'][:200]}...\n"
         
         # Base metadata
         base_metadata = {
            "external_id": cve_id,
            "name": f"{cve_id} - {description[:50]}...",
            "vendor": ", ".join(list(vendors)[:3]) if vendors else "Unknown",
            "product": ", ".join(affected_products[:3]) if affected_products else "Unknown",
            "tactics": "exploitation",
            "platforms": ", ".join(affected_products[:3]) if affected_products else "Unknown",
            "source": "NVD",
            "cvss_score": str(cvss_v3 or cvss_v2 or 0),
            "severity": severity,
            "cwe": ", ".join(cwe_ids[:3]) if cwe_ids else "N/A",
            "published": cve.get("published", ""),
            "last_modified": cve.get("lastModified", ""),
            "mitre_technique_ids": ",".join(mitre_ids) if mitre_ids else "",
            "mitre_technique_names": ",".join(mitre_names) if mitre_names else ""
         }
         
         # Apply semantic chunking
         chunks = chunker.chunk_document(full_text, base_metadata)
         
         for chunk_text, chunk_meta in chunks:
            unique_id = f"nvd_{cve_id}_chunk{chunk_meta['chunk_index']}"
            documents.append(chunk_text)
            ids.append(unique_id)
            metadatas.append(chunk_meta)
         
         processed += 1
         
      except Exception as e:
         continue  # Skip malformed entries
   
   enriched_msg = f" ({enriched_count} enriched with MITRE techniques)" if enriched_count > 0 else ""
   print_status(f"Processed {processed:,} NVD CVE into {len(documents):,} semantic chunks (skipped {skipped} duplicates){enriched_msg}", "success")
   return documents, ids, metadatas

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
      
      # Determine if this is a sub-technique and extract parent ID
      is_subtechnique = "." in external_id
      parent_technique_id = external_id.split(".")[0] if is_subtechnique else ""
      
      # Build context header that will be included in each chunk
      context_header = (
         f"MITRE ATT&CK Technique: {name} ({external_id})\n"
         f"Tactics: {', '.join(tactics) if tactics else 'N/A'}\n"
         f"Platforms: {', '.join(platforms) if platforms else 'N/A'}\n"
      )
      
      # Add parent reference for sub-techniques
      if is_subtechnique:
         context_header += f"Parent Technique: {parent_technique_id}\n"
      
      context_header += "---\n"

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
         "is_subtechnique": "true" if is_subtechnique else "false",
         "parent_technique_id": parent_technique_id
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


def process_cisa_data(cisa_data, chunker: SemanticChunker, cve_to_mitre: Dict[str, List[Dict]] = None):
   """Process CISA KEV data with semantic chunking and MITRE enrichment."""
   if not cisa_data:
      return [], [], []
   
   if cve_to_mitre is None:
      cve_to_mitre = {}
      
   print_status("Parsing CISA KEV vulnerabilities with semantic chunking...", "process")

   documents = []
   ids = []
   metadatas = []
   total_vulns = 0
   enriched_count = 0

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
      
      # Check for MITRE technique mapping
      mitre_techniques = cve_to_mitre.get(cve_id.upper(), [])
      mitre_ids = [t["technique_id"] for t in mitre_techniques]
      mitre_names = [t["technique_name"] for t in mitre_techniques]
      
      if mitre_techniques:
         enriched_count += 1
      
      # Build comprehensive document
      context_header = (
         f"CISA Known Exploited Vulnerability: {name}\n"
         f"CVE ID: {cve_id}\n"
         f"Vendor: {vendor} | Product: {product}\n"
         f"Date Added to KEV: {date_added}\n"
         f"Ransomware Use: {known_ransomware}\n"
      )
      
      # Add MITRE mapping if available
      if mitre_techniques:
         mitre_list = ', '.join([f"{t['technique_id']} ({t['technique_name']})" for t in mitre_techniques])
         context_header += f"Related MITRE Techniques: {mitre_list}\n"
      
      context_header += "---\n"
      
      full_text = context_header + f"Description: {description}"
      
      if required_action:
         full_text += f"\n\n### Required Action\n{required_action}"
      
      if notes:
         full_text += f"\n\n### Notes\n{notes}"
      
      # Add MITRE context if available
      if mitre_techniques:
         full_text += f"\n\n### Related MITRE ATT&CK Techniques\n"
         for tech in mitre_techniques:
            full_text += f"- {tech['technique_id']} ({tech['technique_name']}): {tech['context'][:200]}...\n"
      
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
         "ransomware_use": known_ransomware,
         "mitre_technique_ids": ",".join(mitre_ids) if mitre_ids else "",
         "mitre_technique_names": ",".join(mitre_names) if mitre_names else ""
      }

      # Apply semantic chunking
      chunks = chunker.chunk_document(full_text, base_metadata)
      
      for chunk_text, chunk_meta in chunks:
         unique_id = f"cve_{cve_id}_chunk{chunk_meta['chunk_index']}"
         documents.append(chunk_text)
         ids.append(unique_id)
         metadatas.append(chunk_meta)

   enriched_msg = f" ({enriched_count} enriched with MITRE techniques)" if enriched_count > 0 else ""
   print_status(f"Processed {total_vulns} CISA vulnerabilities into {len(documents)} semantic chunks{enriched_msg}.", "success")
   return documents, ids, metadatas


def parse_arguments():
   """Parse command-line arguments for data ingestion."""
   parser = argparse.ArgumentParser(
      description="IntelGPT Data Ingestion Pipeline - MITRE ATT&CK, CISA KEV, and NVD",
      formatter_class=argparse.RawDescriptionHelpFormatter,
      epilog="""
Examples:
  python ingest_data.py                    # MITRE + CISA only (fast)
  python ingest_data.py --nvd              # MITRE + CISA + NVD (all CVE)
  python ingest_data.py --nvd --days 90    # MITRE + CISA + CVE from last 90 days
  python ingest_data.py --nvd --cvss 7.0   # MITRE + CISA + HIGH/CRITICAL CVE only
  python ingest_data.py --nvd-api-key YOUR_KEY --nvd  # Faster NVD download with API key
      """
   )
   
   parser.add_argument(
      "--nvd", 
      action="store_true",
      help="Include NVD (National Vulnerability Database) - adds ~50k+ CVE"
   )
   
   parser.add_argument(
      "--nvd-api-key",
      type=str,
      default=None,
      help="NVD API key for faster rate limits (get one at https://nvd.nist.gov/developers/request-an-api-key)"
   )
   
   parser.add_argument(
      "--days",
      type=int,
      default=None,
      help="Only fetch CVE modified in last N days (reduces download time)"
   )
   
   parser.add_argument(
      "--cvss",
      type=float,
      default=NVD_MIN_CVSS_SCORE,
      help=f"Minimum CVSS score for NVD CVE (default: {NVD_MIN_CVSS_SCORE})"
   )
   
   parser.add_argument(
      "--skip-mitre",
      action="store_true",
      help="Skip MITRE ATT&CK data (useful for updating CVE only)"
   )
   
   parser.add_argument(
      "--skip-cisa",
      action="store_true", 
      help="Skip CISA KEV data"
   )
   
   return parser.parse_args()


def main():
   clear_screen()
   print_banner()
   
   # Parse command-line arguments
   args = parse_arguments()
   
   print_status("Data Sources Configuration:", "info")
   print(f"   {Colors.CYAN}→{Colors.ENDC} MITRE ATT&CK: {'Disabled' if args.skip_mitre else 'Enabled'}")
   print(f"   {Colors.CYAN}→{Colors.ENDC} CISA KEV: {'Disabled' if args.skip_cisa else 'Enabled'}")
   print(f"   {Colors.CYAN}→{Colors.ENDC} NVD: {'Enabled' if args.nvd else 'Disabled'}")
   if args.nvd:
      print(f"   {Colors.CYAN}→{Colors.ENDC} NVD Filter: CVSS >= {args.cvss}" + (f", Last {args.days} days" if args.days else ""))
      print(f"   {Colors.CYAN}→{Colors.ENDC} NVD API Key: {'Provided ✓' if args.nvd_api_key else 'Not provided (slower)'}")
   print()

   # Initialize semantic chunker
   print_status("Initializing Semantic Chunker...", "process")
   chunker = SemanticChunker(
      chunk_size=CHUNK_SIZE,
      overlap=CHUNK_OVERLAP,
      min_size=MIN_CHUNK_SIZE
   )
   print_status(f"Chunker configured: size={CHUNK_SIZE}, overlap={CHUNK_OVERLAP}", "success")

   documents = []
   ids = []
   metadatas = []
   cisa_cve_ids = set()  # Track CISA CVE IDs to avoid duplicates with NVD
   cve_to_mitre = {}  # Mapping of CVE ID to MITRE techniques

   # Download and process MITRE data
   if not args.skip_mitre:
      mitre_data = download_mitre_data()
      
      # Build CVE to MITRE mapping BEFORE processing
      print_status("Building CVE→MITRE ATT&CK mapping...", "process")
      cve_to_mitre = build_cve_to_mitre_mapping(mitre_data)
      print_status(f"Found {len(cve_to_mitre)} CVE with MITRE technique references.", "success")
      
      mitre_docs, mitre_ids, mitre_metas = process_data(mitre_data, chunker)
      documents.extend(mitre_docs)
      ids.extend(mitre_ids)
      metadatas.extend(mitre_metas)

   # Download and process CISA data
   if not args.skip_cisa:
      cisa_data = download_cisa_data()
      cisa_docs, cisa_ids, cisa_metas = process_cisa_data(cisa_data, chunker, cve_to_mitre)
      documents.extend(cisa_docs)
      ids.extend(cisa_ids)
      metadatas.extend(cisa_metas)
      
      # Extract CISA CVE IDs for deduplication with NVD
      for meta in cisa_metas:
         cve_id = meta.get("external_id", "")
         if cve_id.startswith("CVE-"):
            cisa_cve_ids.add(cve_id)
   
   # Download and process NVD data
   if args.nvd:
      nvd_data = download_nvd_data(
         api_key=args.nvd_api_key,
         days_back=args.days,
         min_cvss=args.cvss
      )
      nvd_docs, nvd_ids, nvd_metas = process_nvd_data(nvd_data, chunker, cisa_cve_ids, cve_to_mitre)
      documents.extend(nvd_docs)
      ids.extend(nvd_ids)
      metadatas.extend(nvd_metas)

   if not documents:
      print_status("No data to ingest. Check your options.", "error")
      sys.exit(1)

   print_status(f"Total Knowledge Base Size: {len(documents):,} semantic chunks.", "info")

   # Display source distribution
   source_counts = {}
   for meta in metadatas:
      src = meta.get("source", "unknown")
      source_counts[src] = source_counts.get(src, 0) + 1
   
   print_status("Distribution by source:", "info")
   for src, count in sorted(source_counts.items(), key=lambda x: -x[1]):
      print(f"   {Colors.CYAN}→{Colors.ENDC} {src}: {count:,} chunks")

   # Display chunking statistics
   chunk_types = {}
   for meta in metadatas:
      ct = meta.get("chunk_type", "unknown")
      chunk_types[ct] = chunk_types.get(ct, 0) + 1
   
   print_status("Distribution by chunk type:", "info")
   for ct, count in sorted(chunk_types.items(), key=lambda x: -x[1]):
      print(f"   {Colors.CYAN}→{Colors.ENDC} {ct}: {count:,}")

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

   # Final summary
   print(f"\n{Colors.HEADER}{Colors.BOLD}==========================================")
   print(f"SYSTEM READY. {len(documents):,} Items Indexed.")
   print(f"Sources: {', '.join(source_counts.keys())}")
   print(f"Database saved at: {DB_PATH}")
   print(f"=========================================={Colors.ENDC}\n")


if __name__ == "__main__":
   main()