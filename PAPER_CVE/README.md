# CVE Vector Database Setup

This project fetches CVE data from 2025, creates vector embeddings, and stores them in a vector database for semantic search.

## Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Fetch 50 CVEs from 2025:
```bash
python fetch_cves.py
```

3. Create vector embeddings and store in database:
```bash
python create_embeddings.py
```

## Project Structure

- `fetch_cves.py` - Fetches CVE files from GitHub repository
- `create_embeddings.py` - Creates embeddings and stores in ChromaDB
- `data/cves_2025.json` - Structured CVE data
- `chroma_db/` - Vector database storage

## Vector Database

- **Database**: ChromaDB
- **Embedding Model**: sentence-transformers/all-MiniLM-L6-v2
- **Collection**: cve_embeddings

## Usage

The vector database can be queried for:
- Technology stack matching
- Semantic search for vulnerabilities
- CVE retrieval based on descriptions

