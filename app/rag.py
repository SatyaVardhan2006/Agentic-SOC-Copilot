import os
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


class PlaybookDocument:
    def __init__(self, filename: str, raw_text: str):
        self.filename = filename
        self.raw_text = raw_text
        self.playbook_id = "UNKNOWN"
        self.category = "GENERAL"
        self.title = filename
        self._parse_headers()

    def _parse_headers(self):
        lines = self.raw_text.strip().split("\n")
        for line in lines:
            if line.startswith("# PLAYBOOK:"):
                self.title = line.replace("# PLAYBOOK:", "").strip()
            elif line.startswith("PLAYBOOK_ID:"):
                self.playbook_id = line.replace("PLAYBOOK_ID:", "").strip()
            elif line.startswith("CATEGORY:"):
                self.category = line.replace("CATEGORY:", "").strip()


class RAGEngine:
    """
    Lightweight, deterministic RAG engine using TF-IDF vectorization and
    cosine similarity for security playbook knowledge retrieval.
    """
    def __init__(self, kb_dir: Optional[str] = None):
        if kb_dir is None:
            # Default to data/knowledge_base relative to project root
            base_dir = Path(__file__).resolve().parent.parent
            kb_dir = str(base_dir / "data" / "knowledge_base")
        self.kb_dir = Path(kb_dir)
        self.documents: List[PlaybookDocument] = []
        self.vectorizer: Optional[TfidfVectorizer] = None
        self.doc_vectors = None
        self.load_and_index()

    def load_and_index(self):
        """Load all .txt files from the knowledge base directory and build the vector index."""
        self.documents = []
        if not self.kb_dir.exists():
            return

        for file_path in self.kb_dir.glob("*.txt"):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()
                    self.documents.append(PlaybookDocument(file_path.name, content))
            except Exception as e:
                print(f"[RAG WARNING] Failed to read {file_path}: {e}")

        if self.documents:
            corpus = [doc.raw_text for doc in self.documents]
            self.vectorizer = TfidfVectorizer(
                stop_words="english",
                ngram_range=(1, 2),
                sublinear_tf=True
            )
            self.doc_vectors = self.vectorizer.fit_transform(corpus)

    def search(self, query: str, top_k: int = 2) -> List[Dict[str, Any]]:
        """
        Query the playbook corpus and return the top_k most relevant playbooks
        with normalized relevance scores and key procedural snippets.
        """
        if not self.documents or self.vectorizer is None or self.doc_vectors is None:
            return []

        query_vec = self.vectorizer.transform([query])
        scores = cosine_similarity(query_vec, self.doc_vectors)[0]

        # Rank indices by score descending
        ranked_indices = scores.argsort()[::-1]

        results = []
        for idx in ranked_indices[:top_k]:
            score = float(scores[idx])
            doc = self.documents[idx]
            
            # Extract actionable containment snippet
            snippet = self._extract_relevant_snippet(doc.raw_text, query)

            results.append({
                "playbook_id": doc.playbook_id,
                "title": doc.title,
                "category": doc.category,
                "score": round(score, 4),
                "filename": doc.filename,
                "content_snippet": snippet
            })

        return results

    def _extract_relevant_snippet(self, text: str, query: str) -> str:
        """Extract the most relevant section (e.g. Recommended Containment) from the playbook."""
        # Check if containment section exists
        containment_match = re.search(r"(## Recommended Containment & Remediation Actions[\s\S]+?)(?=\n## |\Z)", text)
        if containment_match:
            snippet = containment_match.group(1).strip()
            # Return first ~500 chars cleanly
            if len(snippet) > 600:
                snippet = snippet[:600] + "..."
            return snippet

        # Fallback to first section
        lines = [l for l in text.split("\n") if l.strip() and not l.startswith("#") and not l.startswith("PLAYBOOK")]
        return "\n".join(lines[:6])


# Global singleton instance
_rag_engine: Optional[RAGEngine] = None


def get_rag_engine() -> RAGEngine:
    global _rag_engine
    if _rag_engine is None:
        _rag_engine = RAGEngine()
    return _rag_engine
