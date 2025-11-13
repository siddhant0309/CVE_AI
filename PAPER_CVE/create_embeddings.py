"""
Script to create vector embeddings for CVEs and store in vector database
Uses sentence-transformers for embeddings and ChromaDB for vector storage
"""

import json
import os
from pathlib import Path
from typing import List, Dict
import chromadb
from chromadb.config import Settings
from sentence_transformers import SentenceTransformer

# Initialize embedding model
print("Loading embedding model...")
EMBEDDING_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
model = SentenceTransformer(EMBEDDING_MODEL)
print(f"[OK] Loaded model: {EMBEDDING_MODEL}\n")

# Initialize ChromaDB (new API)
print("Initializing vector database...")
chroma_client = chromadb.PersistentClient(path="./chroma_db")

# Create or get collection
COLLECTION_NAME = "cve_embeddings"
try:
    collection = chroma_client.get_collection(name=COLLECTION_NAME)
    print(f"[OK] Using existing collection: {COLLECTION_NAME}")
except:
    collection = chroma_client.create_collection(name=COLLECTION_NAME)
    print(f"[OK] Created new collection: {COLLECTION_NAME}")
print()

def prepare_text_for_embedding(cve: Dict) -> str:
    """Prepare text from CVE data for embedding"""
    parts = []
    
    # CVE ID
    parts.append(f"CVE: {cve.get('cve_id', '')}")
    
    # Description
    if cve.get('description'):
        parts.append(f"Description: {cve['description']}")
    
    # Affected products/technologies
    if cve.get('technologies'):
        tech_list = ', '.join(cve['technologies'])
        parts.append(f"Technologies: {tech_list}")
    
    if cve.get('affected_products'):
        products_list = ', '.join(cve['affected_products'])
        parts.append(f"Affected Products: {products_list}")
    
    # Severity and CVSS
    if cve.get('severity'):
        parts.append(f"Severity: {cve['severity']}")
    
    if cve.get('cvss_v3_score'):
        parts.append(f"CVSS v3 Score: {cve['cvss_v3_score']}")
    
    if cve.get('cvss_v2_score'):
        parts.append(f"CVSS v2 Score: {cve['cvss_v2_score']}")
    
    # Solution (if available)
    if cve.get('solution'):
        parts.append(f"Solution: {cve['solution']}")
    
    return " | ".join(parts)

def create_embeddings_and_store(cves: List[Dict]):
    """Create embeddings for CVEs and store in vector database"""
    print(f"=== Creating embeddings for {len(cves)} CVEs ===\n")
    
    documents = []
    metadatas = []
    ids = []
    
    for i, cve in enumerate(cves, 1):
        cve_id = cve.get('cve_id', f'CVE-UNKNOWN-{i}')
        print(f"[{i}/{len(cves)}] Processing {cve_id}...", end=' ')
        
        # Prepare text for embedding
        text = prepare_text_for_embedding(cve)
        
        # Create metadata
        metadata = {
            'cve_id': cve_id,
            'description': cve.get('description', '')[:500],  # Truncate for metadata
            'cvss_v3_score': cve.get('cvss_v3_score'),
            'cvss_v2_score': cve.get('cvss_v2_score'),
            'severity': cve.get('severity', ''),
            'technologies': ', '.join(cve.get('technologies', [])),
            'affected_products': ', '.join(cve.get('affected_products', [])),
            'has_solution': bool(cve.get('solution')),
            'kev_flag': cve.get('kev_flag', False),
            'epss_score': cve.get('epss_score')
        }
        
        documents.append(text)
        metadatas.append(metadata)
        ids.append(cve_id)
        
        print("[OK]")
    
    print("\n=== Generating embeddings (this may take a moment)... ===")
    
    # Generate embeddings in batches for efficiency
    embeddings = model.encode(documents, show_progress_bar=True, batch_size=32)
    
    print(f"\n=== Storing embeddings in vector database ===")
    
    # Add to collection
    collection.add(
        embeddings=embeddings.tolist(),
        documents=documents,
        metadatas=metadatas,
        ids=ids
    )
    
    print(f"[OK] Successfully stored {len(cves)} CVE embeddings\n")
    print("[OK] Database persisted to disk (auto-saved)\n")

def verify_database():
    """Verify the vector database setup"""
    print("=== Verifying Vector Database ===\n")
    
    count = collection.count()
    print(f"Total CVEs in database: {count}")
    
    # Get a sample query
    sample_cve = collection.get(limit=1)
    if sample_cve['ids']:
        print(f"\nSample CVE ID: {sample_cve['ids'][0]}")
        print(f"Sample Metadata keys: {list(sample_cve['metadatas'][0].keys())}")
    
    # Test similarity search
    print("\n=== Testing Similarity Search ===")
    test_query = "Python vulnerability SQL injection"
    print(f"Test query: '{test_query}'")
    
    query_embedding = model.encode([test_query])
    results = collection.query(
        query_embeddings=query_embedding.tolist(),
        n_results=3
    )
    
    print(f"\nTop 3 similar CVEs:")
    for i, (cve_id, distance) in enumerate(zip(results['ids'][0], results['distances'][0]), 1):
        print(f"  {i}. {cve_id} (distance: {distance:.4f})")
    
    print("\n[OK] Vector database is working correctly!\n")

if __name__ == "__main__":
    # Load CVEs from JSON file
    cve_file = Path("data/cves_2025.json")
    
    if not cve_file.exists():
        print(f"Error: {cve_file} not found!")
        print("Please run fetch_cves.py first to download CVE data.")
        exit(1)
    
    print(f"Loading CVEs from {cve_file}...")
    with open(cve_file, 'r', encoding='utf-8') as f:
        cves = json.load(f)
    
    print(f"[OK] Loaded {len(cves)} CVEs\n")
    
    # Create embeddings and store
    create_embeddings_and_store(cves)
    
    # Verify database
    verify_database()
    
    print("=== Setup Complete ===")
    print("Vector database ready for CVE retrieval!")

