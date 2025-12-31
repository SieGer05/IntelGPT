"""
Reranker Module
===============
Implements Cross-Encoder reranking for improved retrieval accuracy.

Cross-encoders process query-document pairs together, allowing for:
- Better semantic understanding of query-document relevance
- Handling of complex queries with multiple concepts
- More accurate relevance scoring than bi-encoders

This module uses the sentence-transformers cross-encoder models.
"""

from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
import time


@dataclass
class RerankResult:
    """Represents a reranked document with its score."""
    doc_id: str
    document: str
    metadata: Dict[str, Any]
    original_score: float  # Score before reranking (hybrid/vector/bm25)
    rerank_score: float    # Score from cross-encoder
    original_rank: int
    new_rank: int


class CrossEncoderReranker:
    """
    Cross-Encoder Reranker for post-retrieval document reranking.
    
    Cross-encoders are more accurate than bi-encoders because they:
    - Process query and document together (cross-attention)
    - Capture fine-grained semantic relationships
    - Better handle negation, qualifiers, and complex queries
    
    Trade-off: Slower than bi-encoders, so we rerank only top-k candidates.
    """
    
    # Recommended models (sorted by quality/speed trade-off):
    # - "cross-encoder/ms-marco-MiniLM-L-6-v2"  (fast, good quality)
    # - "cross-encoder/ms-marco-MiniLM-L-12-v2" (balanced)
    # - "BAAI/bge-reranker-base"                (high quality)
    # - "BAAI/bge-reranker-large"               (best quality, slower)
    
    DEFAULT_MODEL = "cross-encoder/ms-marco-MiniLM-L-6-v2"
    
    def __init__(
        self,
        model_name: str = DEFAULT_MODEL,
        top_k: int = 5,
        batch_size: int = 16,
        min_score_threshold: float = 0.0,
        enabled: bool = True
    ):
        """
        Initialize the Cross-Encoder Reranker.
        
        Args:
            model_name: HuggingFace model name for cross-encoder
            top_k: Number of top documents to return after reranking
            batch_size: Batch size for inference (affects speed/memory)
            min_score_threshold: Minimum rerank score to include document
            enabled: Whether reranking is active (for easy toggling)
        """
        self.model_name = model_name
        self.top_k = top_k
        self.batch_size = batch_size
        self.min_score_threshold = min_score_threshold
        self.enabled = enabled
        
        self.model = None
        self._is_loaded = False
        self._load_time = 0.0
    
    def load_model(self) -> bool:
        """
        Load the cross-encoder model.
        Called lazily on first use or explicitly at startup.
        
        Returns:
            True if model loaded successfully
        """
        if self._is_loaded:
            return True
        
        try:
            start_time = time.time()
            
            from sentence_transformers import CrossEncoder
            
            print(f"[RERANKER] Loading model: {self.model_name}")
            self.model = CrossEncoder(self.model_name)
            
            self._load_time = time.time() - start_time
            self._is_loaded = True
            print(f"[RERANKER] Model loaded in {self._load_time:.2f}s")
            
            return True
            
        except Exception as e:
            print(f"[RERANKER] Failed to load model: {e}")
            self.enabled = False
            return False
    
    def rerank(
        self,
        query: str,
        documents: List[Dict[str, Any]],
        original_scores: Optional[List[float]] = None
    ) -> List[RerankResult]:
        """
        Rerank documents based on query relevance using cross-encoder.
        
        Args:
            query: The search query
            documents: List of documents with 'id', 'document', 'metadata' keys
            original_scores: Optional list of original retrieval scores
            
        Returns:
            List of RerankResult sorted by rerank_score (descending)
        """
        if not self.enabled:
            # Return documents as-is if reranking is disabled
            return self._passthrough(documents, original_scores)
        
        if not self._is_loaded:
            if not self.load_model():
                return self._passthrough(documents, original_scores)
        
        if not documents:
            return []
        
        # Prepare query-document pairs for cross-encoder
        pairs = [(query, doc.get("document", "")) for doc in documents]
        
        # Get rerank scores
        start_time = time.time()
        
        try:
            # CrossEncoder.predict returns relevance scores
            scores = self.model.predict(pairs, batch_size=self.batch_size)
            
            inference_time = time.time() - start_time
            print(f"[RERANKER] Scored {len(pairs)} documents in {inference_time:.3f}s")
            
        except Exception as e:
            print(f"[RERANKER] Scoring failed: {e}")
            return self._passthrough(documents, original_scores)
        
        # Build rerank results
        results = []
        for i, doc in enumerate(documents):
            original_score = original_scores[i] if original_scores else 0.0
            rerank_score = float(scores[i])
            
            # Apply minimum threshold filter
            if rerank_score < self.min_score_threshold:
                continue
            
            results.append(RerankResult(
                doc_id=doc.get("id", f"doc_{i}"),
                document=doc.get("document", ""),
                metadata=doc.get("metadata", {}),
                original_score=original_score,
                rerank_score=rerank_score,
                original_rank=i + 1,
                new_rank=0  # Will be set after sorting
            ))
        
        # Sort by rerank score (descending)
        results.sort(key=lambda x: x.rerank_score, reverse=True)
        
        # Assign new ranks
        for i, result in enumerate(results):
            result.new_rank = i + 1
        
        # Return top_k results
        return results[:self.top_k]
    
    def _passthrough(
        self,
        documents: List[Dict[str, Any]],
        original_scores: Optional[List[float]] = None
    ) -> List[RerankResult]:
        """
        Passthrough mode when reranking is disabled.
        Returns documents in original order with placeholder scores.
        """
        results = []
        for i, doc in enumerate(documents):
            original_score = original_scores[i] if original_scores else 0.0
            results.append(RerankResult(
                doc_id=doc.get("id", f"doc_{i}"),
                document=doc.get("document", ""),
                metadata=doc.get("metadata", {}),
                original_score=original_score,
                rerank_score=original_score,  # Use original score
                original_rank=i + 1,
                new_rank=i + 1
            ))
        return results[:self.top_k]
    
    def explain_reranking(
        self,
        query: str,
        documents: List[Dict[str, Any]],
        original_scores: Optional[List[float]] = None
    ) -> str:
        """
        Rerank and return a human-readable explanation.
        Useful for debugging and understanding reranking behavior.
        """
        results = self.rerank(query, documents, original_scores)
        
        lines = [
            f"Query: '{query}'",
            f"Reranker: {self.model_name}",
            "=" * 60
        ]
        
        for result in results:
            rank_change = result.original_rank - result.new_rank
            change_str = f"+{rank_change}" if rank_change > 0 else str(rank_change)
            
            lines.append(f"\n#{result.new_rank}: {result.metadata.get('name', 'Unknown')}")
            lines.append(f"  Original Rank: {result.original_rank} ({change_str})")
            lines.append(f"  Rerank Score:  {result.rerank_score:.4f}")
            lines.append(f"  Original Score: {result.original_score:.4f}")
        
        return "\n".join(lines)
    
    @property
    def is_ready(self) -> bool:
        """Check if reranker is loaded and ready."""
        return self._is_loaded and self.enabled
    
    def get_stats(self) -> Dict[str, Any]:
        """Get reranker statistics."""
        return {
            "enabled": self.enabled,
            "is_loaded": self._is_loaded,
            "model_name": self.model_name,
            "top_k": self.top_k,
            "load_time_seconds": self._load_time
        }


# Convenience function for quick reranking
def rerank_documents(
    query: str,
    documents: List[Dict[str, Any]],
    top_k: int = 5,
    model_name: str = CrossEncoderReranker.DEFAULT_MODEL
) -> List[RerankResult]:
    """
    Quick reranking function for one-off use.
    
    For production use, instantiate CrossEncoderReranker once
    and reuse it to avoid model reloading.
    """
    reranker = CrossEncoderReranker(model_name=model_name, top_k=top_k)
    return reranker.rerank(query, documents)
