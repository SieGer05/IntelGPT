"""
Hybrid Search Module
====================
Combines semantic vector search (embeddings) with keyword-based BM25 search
for improved retrieval accuracy. This approach leverages:
- Semantic Search: Captures meaning and context
- BM25 Search: Matches exact keywords and terms (great for IDs, technical terms)

The final ranking uses Reciprocal Rank Fusion (RRF) to combine both results.

Post-Retrieval Reranking:
- Uses Cross-Encoder models for more accurate relevance scoring
- Reorders top candidates based on query-document semantic similarity
"""

import math
import re
from collections import defaultdict
from typing import List, Dict, Any, Tuple, Optional
from dataclasses import dataclass

# Import reranker module
from reranker import CrossEncoderReranker, RerankResult


@dataclass
class SearchResult:
    """Represents a single search result with combined scoring."""
    doc_id: str
    document: str
    metadata: Dict[str, Any]
    vector_score: float = 0.0
    bm25_score: float = 0.0
    hybrid_score: float = 0.0
    vector_rank: int = 0
    bm25_rank: int = 0


class BM25Index:
    """
    BM25 (Best Matching 25) implementation for keyword-based search.
    
    BM25 is a probabilistic ranking function that considers:
    - Term Frequency (TF): How often a term appears in a document
    - Inverse Document Frequency (IDF): How rare a term is across all documents
    - Document Length Normalization: Adjusts for document length
    """
    
    def __init__(self, k1: float = 1.5, b: float = 0.75):
        """
        Initialize BM25 index.
        
        Args:
            k1: Term frequency saturation parameter (1.2-2.0 typical)
            b: Document length normalization (0-1, 0.75 typical)
        """
        self.k1 = k1
        self.b = b
        
        # Index structures
        self.documents: Dict[str, str] = {}  # doc_id -> document text
        self.metadata: Dict[str, Dict] = {}  # doc_id -> metadata
        self.doc_lengths: Dict[str, int] = {}  # doc_id -> token count
        self.avg_doc_length: float = 0.0
        self.doc_count: int = 0
        
        # Inverted index: term -> {doc_id: term_frequency}
        self.inverted_index: Dict[str, Dict[str, int]] = defaultdict(dict)
        
        # Document frequency: term -> number of documents containing term
        self.doc_freq: Dict[str, int] = defaultdict(int)
        
        self._is_built = False
    
    def _tokenize(self, text: str) -> List[str]:
        """
        Tokenize text for BM25 indexing.
        Handles technical terms, IDs, and common patterns in cybersecurity docs.
        """
        # Convert to lowercase
        text = text.lower()
        
        # Preserve technical IDs (CVE-XXXX-XXXX, TXXXX, etc.)
        # Replace hyphens in IDs with a placeholder to keep them together
        text = re.sub(r'(cve-\d{4}-\d+)', lambda m: m.group(1).replace('-', '_CVE_'), text)
        text = re.sub(r'(t\d{4}(?:\.\d{3})?)', lambda m: m.group(1).replace('.', '_MITRE_'), text)
        
        # Tokenize: split on non-alphanumeric, keep underscores
        tokens = re.findall(r'[a-z0-9_]+', text)
        
        # Restore IDs
        tokens = [t.replace('_cve_', '-').replace('_mitre_', '.') for t in tokens]
        
        # Filter very short tokens (noise) but keep IDs
        tokens = [t for t in tokens if len(t) > 1 or t.isdigit()]
        
        return tokens
    
    def build_index(self, documents: List[Tuple[str, str, Dict[str, Any]]]) -> None:
        """
        Build BM25 index from documents.
        
        Args:
            documents: List of (doc_id, document_text, metadata) tuples
        """
        self.documents.clear()
        self.metadata.clear()
        self.doc_lengths.clear()
        self.inverted_index.clear()
        self.doc_freq.clear()
        
        total_length = 0
        
        for doc_id, doc_text, meta in documents:
            self.documents[doc_id] = doc_text
            self.metadata[doc_id] = meta
            
            tokens = self._tokenize(doc_text)
            self.doc_lengths[doc_id] = len(tokens)
            total_length += len(tokens)
            
            # Count term frequencies in this document
            term_freq: Dict[str, int] = defaultdict(int)
            for token in tokens:
                term_freq[token] += 1
            
            # Update inverted index and document frequencies
            for term, freq in term_freq.items():
                self.inverted_index[term][doc_id] = freq
                
            # Update document frequency (count unique terms per doc)
            for term in term_freq.keys():
                self.doc_freq[term] += 1
        
        self.doc_count = len(documents)
        self.avg_doc_length = total_length / self.doc_count if self.doc_count > 0 else 0
        self._is_built = True
    
    def _calculate_idf(self, term: str) -> float:
        """Calculate Inverse Document Frequency for a term."""
        if term not in self.doc_freq:
            return 0.0
        
        df = self.doc_freq[term]
        # Standard BM25 IDF formula with smoothing
        idf = math.log((self.doc_count - df + 0.5) / (df + 0.5) + 1.0)
        return max(0.0, idf)  # Ensure non-negative
    
    def search(self, query: str, top_k: int = 10) -> List[Tuple[str, float]]:
        """
        Search documents using BM25 scoring.
        
        Args:
            query: Search query string
            top_k: Number of top results to return
            
        Returns:
            List of (doc_id, bm25_score) tuples, sorted by score descending
        """
        if not self._is_built:
            return []
        
        query_tokens = self._tokenize(query)
        if not query_tokens:
            return []
        
        scores: Dict[str, float] = defaultdict(float)
        
        for term in query_tokens:
            if term not in self.inverted_index:
                continue
            
            idf = self._calculate_idf(term)
            
            for doc_id, tf in self.inverted_index[term].items():
                doc_len = self.doc_lengths[doc_id]
                
                # BM25 scoring formula
                numerator = tf * (self.k1 + 1)
                denominator = tf + self.k1 * (1 - self.b + self.b * (doc_len / self.avg_doc_length))
                
                scores[doc_id] += idf * (numerator / denominator)
        
        # Sort by score descending
        sorted_results = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        return sorted_results[:top_k]


class HybridSearchEngine:
    """
    Hybrid Search Engine combining vector search and BM25.
    
    Uses Reciprocal Rank Fusion (RRF) to combine rankings:
    RRF_score = sum(1 / (k + rank_i)) for each ranking method
    
    This approach is robust and doesn't require score normalization.
    
    Includes optional Cross-Encoder reranking for improved accuracy.
    """
    
    def __init__(
        self,
        collection,  # ChromaDB collection
        embedding_model,  # SentenceTransformer model
        vector_weight: float = 0.5,
        bm25_weight: float = 0.5,
        rrf_k: int = 60,
        rerank_enabled: bool = True,
        rerank_model: str = "cross-encoder/ms-marco-MiniLM-L-6-v2",
        rerank_top_k: int = 5
    ):
        """
        Initialize Hybrid Search Engine.
        
        Args:
            collection: ChromaDB collection for vector search
            embedding_model: SentenceTransformer model for embeddings
            vector_weight: Weight for vector search results (0-1)
            bm25_weight: Weight for BM25 results (0-1)
            rrf_k: RRF constant (higher = more emphasis on top ranks)
            rerank_enabled: Whether to enable cross-encoder reranking
            rerank_model: HuggingFace model name for cross-encoder
            rerank_top_k: Number of documents to return after reranking
        """
        self.collection = collection
        self.embedding_model = embedding_model
        self.vector_weight = vector_weight
        self.bm25_weight = bm25_weight
        self.rrf_k = rrf_k
        
        # Initialize BM25 index
        self.bm25_index = BM25Index()
        self._index_built = False
        
        # Initialize Reranker
        self.rerank_enabled = rerank_enabled
        self.reranker = None
        if rerank_enabled:
            self.reranker = CrossEncoderReranker(
                model_name=rerank_model,
                top_k=rerank_top_k,
                enabled=True
            )
    
    def build_bm25_index(self) -> int:
        """
        Build BM25 index from ChromaDB collection.
        Should be called once at startup.
        
        Returns:
            Number of documents indexed
        """
        # Fetch all documents from ChromaDB
        all_docs = self.collection.get(include=["documents", "metadatas"])
        
        if not all_docs["ids"]:
            print("[HYBRID] No documents found in collection")
            return 0
        
        documents = []
        for i, doc_id in enumerate(all_docs["ids"]):
            doc_text = all_docs["documents"][i] if all_docs["documents"] else ""
            metadata = all_docs["metadatas"][i] if all_docs["metadatas"] else {}
            documents.append((doc_id, doc_text, metadata))
        
        self.bm25_index.build_index(documents)
        self._index_built = True
        print(f"[HYBRID] BM25 index built with {len(documents)} documents")
        
        # Load reranker model if enabled
        if self.reranker and self.rerank_enabled:
            self.reranker.load_model()
        
        return len(documents)
    
    def _vector_search(self, query: str, n_results: int, where_filter: Optional[Dict] = None) -> List[SearchResult]:
        """Perform vector similarity search."""
        query_vector = self.embedding_model.encode([query]).tolist()
        
        if where_filter:
            results = self.collection.query(
                query_embeddings=query_vector,
                n_results=n_results,
                where=where_filter,
                include=["documents", "metadatas", "distances"]
            )
        else:
            results = self.collection.query(
                query_embeddings=query_vector,
                n_results=n_results,
                include=["documents", "metadatas", "distances"]
            )
        
        search_results = []
        if results["ids"] and results["ids"][0]:
            for i, doc_id in enumerate(results["ids"][0]):
                # ChromaDB returns distances (lower = better), convert to similarity
                distance = results["distances"][0][i] if results["distances"] else 0
                similarity = 1 / (1 + distance)  # Convert distance to similarity score
                
                search_results.append(SearchResult(
                    doc_id=doc_id,
                    document=results["documents"][0][i],
                    metadata=results["metadatas"][0][i],
                    vector_score=similarity,
                    vector_rank=i + 1
                ))
        
        return search_results
    
    def _bm25_search(self, query: str, n_results: int) -> List[SearchResult]:
        """Perform BM25 keyword search."""
        if not self._index_built:
            return []
        
        bm25_results = self.bm25_index.search(query, n_results)
        
        search_results = []
        for rank, (doc_id, score) in enumerate(bm25_results, 1):
            search_results.append(SearchResult(
                doc_id=doc_id,
                document=self.bm25_index.documents[doc_id],
                metadata=self.bm25_index.metadata[doc_id],
                bm25_score=score,
                bm25_rank=rank
            ))
        
        return search_results
    
    def _reciprocal_rank_fusion(
        self,
        vector_results: List[SearchResult],
        bm25_results: List[SearchResult]
    ) -> List[SearchResult]:
        """
        Combine results using Reciprocal Rank Fusion (RRF).
        
        RRF is robust because it:
        - Doesn't require score normalization
        - Handles different score scales gracefully
        - Emphasizes agreement between methods
        """
        # Create lookup by doc_id
        combined: Dict[str, SearchResult] = {}
        
        # Process vector results
        for result in vector_results:
            combined[result.doc_id] = result
        
        # Process BM25 results and merge
        for result in bm25_results:
            if result.doc_id in combined:
                # Merge scores
                combined[result.doc_id].bm25_score = result.bm25_score
                combined[result.doc_id].bm25_rank = result.bm25_rank
            else:
                combined[result.doc_id] = result
        
        # Calculate hybrid scores using RRF
        for doc_id, result in combined.items():
            rrf_score = 0.0
            
            if result.vector_rank > 0:
                rrf_score += self.vector_weight * (1 / (self.rrf_k + result.vector_rank))
            
            if result.bm25_rank > 0:
                rrf_score += self.bm25_weight * (1 / (self.rrf_k + result.bm25_rank))
            
            result.hybrid_score = rrf_score
        
        # Sort by hybrid score descending
        sorted_results = sorted(combined.values(), key=lambda x: x.hybrid_score, reverse=True)
        return sorted_results
    
    def search(
        self,
        query: str,
        n_results: int = 10,
        where_filter: Optional[Dict] = None,
        search_mode: str = "hybrid",
        use_reranking: bool = True
    ) -> Dict[str, Any]:
        """
        Perform hybrid search combining vector and BM25, with optional reranking.
        
        Args:
            query: Search query
            n_results: Number of results to return
            where_filter: Optional ChromaDB filter
            search_mode: "hybrid", "vector", or "bm25"
            use_reranking: Whether to apply cross-encoder reranking
            
        Returns:
            Dictionary with results and search metadata
        """
        # Expand search pool for better fusion and reranking
        # Reranking works best with more candidates
        pool_size = n_results * 3 if (use_reranking and self.reranker) else n_results * 2
        
        vector_results = []
        bm25_results = []
        
        if search_mode in ["hybrid", "vector"]:
            vector_results = self._vector_search(query, pool_size, where_filter)
        
        if search_mode in ["hybrid", "bm25"] and self._index_built:
            bm25_results = self._bm25_search(query, pool_size)
        
        # Combine results
        if search_mode == "hybrid" and vector_results and bm25_results:
            combined_results = self._reciprocal_rank_fusion(vector_results, bm25_results)
        elif vector_results:
            combined_results = vector_results
        elif bm25_results:
            combined_results = bm25_results
        else:
            combined_results = []
        
        # Apply reranking if enabled
        reranked = False
        rerank_scores = []
        
        if use_reranking and self.reranker and self.rerank_enabled and combined_results:
            # Prepare documents for reranking
            docs_for_rerank = [
                {
                    "id": r.doc_id,
                    "document": r.document,
                    "metadata": r.metadata
                }
                for r in combined_results[:pool_size]
            ]
            original_scores = [r.hybrid_score for r in combined_results[:pool_size]]
            
            # Perform reranking
            rerank_results = self.reranker.rerank(query, docs_for_rerank, original_scores)
            
            if rerank_results:
                reranked = True
                # Rebuild final results from rerank output
                final_results = []
                rerank_scores = []
                
                for rr in rerank_results[:n_results]:
                    # Find original result to preserve all scores
                    original = next((r for r in combined_results if r.doc_id == rr.doc_id), None)
                    if original:
                        final_results.append(original)
                        rerank_scores.append(rr.rerank_score)
                    else:
                        # Fallback: create new SearchResult
                        final_results.append(SearchResult(
                            doc_id=rr.doc_id,
                            document=rr.document,
                            metadata=rr.metadata,
                            hybrid_score=rr.original_score
                        ))
                        rerank_scores.append(rr.rerank_score)
                
                print(f"[RERANK] Applied cross-encoder reranking: {len(rerank_results)} documents scored")
            else:
                # Reranking failed, use original results
                final_results = combined_results[:n_results]
        else:
            # No reranking, use combined results
            final_results = combined_results[:n_results]
        
        # Format output
        result_dict = {
            "ids": [[r.doc_id for r in final_results]],
            "documents": [[r.document for r in final_results]],
            "metadatas": [[r.metadata for r in final_results]],
            "scores": {
                "hybrid": [r.hybrid_score for r in final_results],
                "vector": [r.vector_score for r in final_results],
                "bm25": [r.bm25_score for r in final_results],
                "rerank": rerank_scores if reranked else [0.0] * len(final_results)
            },
            "search_mode": search_mode,
            "vector_results_count": len(vector_results),
            "bm25_results_count": len(bm25_results),
            "reranked": reranked
        }
        
        return result_dict
    
    def explain_search(self, query: str, n_results: int = 5) -> str:
        """
        Perform search and return explanation of ranking.
        Useful for debugging and understanding search behavior.
        """
        results = self.search(query, n_results, search_mode="hybrid", use_reranking=True)
        
        explanation = [
            f"Query: '{query}'",
            f"Reranking: {'Enabled' if results.get('reranked') else 'Disabled'}",
            "=" * 60
        ]
        
        for i, doc_id in enumerate(results["ids"][0]):
            meta = results["metadatas"][0][i]
            explanation.append(f"\n#{i+1}: {meta.get('name', 'Unknown')} ({meta.get('external_id', 'N/A')})")
            explanation.append(f"  Hybrid Score: {results['scores']['hybrid'][i]:.4f}")
            explanation.append(f"  Vector Score: {results['scores']['vector'][i]:.4f}")
            explanation.append(f"  BM25 Score:   {results['scores']['bm25'][i]:.4f}")
            if results.get('reranked') and results['scores']['rerank']:
                explanation.append(f"  Rerank Score: {results['scores']['rerank'][i]:.4f}")
        
        return "\n".join(explanation)
    
    def get_reranker_stats(self) -> Dict[str, Any]:
        """Get reranker statistics and status."""
        if self.reranker:
            return self.reranker.get_stats()
        return {"enabled": False, "is_loaded": False}
