# Patch Path — AI-Powered Cybersecurity Vulnerability Management System

Patch Path is an AI-powered cybersecurity vulnerability management system that helps organizations identify, assess, and mitigate **Common Vulnerabilities and Exposures (CVEs)** across their technology stack. It uses a **multi-agent architecture** to deliver end-to-end vulnerability analysis, risk scoring, and step-by-step mitigation plans—plus downloadable **PDF reports**.

> **Tagline:** *Find the path to your patch.*

---

## Table of Contents
- [Documentation](#documentation)
- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Configuration](#configuration)
- [Project Structure](#project-structure)
- [System Architecture](#System-Architecture)
- [Technologies Used](#technologies-used)

---

## Documentation
Link : https://drive.google.com/file/d/1xA4aF-q29RwziRevT621XtwA--T-rNRD/view?usp=sharing

## Overview

Patch Path enables security teams, students, and sysadmins to:
- Detect technologies from **architecture diagrams** (image input)
- Search CVEs using **RAG + vector similarity**
- Compute risk using **CVSS + EPSS**
- Generate actionable **mitigation roadmaps**
- Export professional **PDF assessment reports**
- Interact via a **chat-based interface** with context memory

### Key Capabilities
- **Tech Stack Detection:** Automatically detects technologies from architecture diagrams using a vision model
- **CVE Search:** Intelligent vulnerability search using a RAG (Retrieval-Augmented Generation) pipeline
- **Risk Assessment:** Calculates risk scores using **CVSS** and **EPSS**
- **Mitigation Planning:** Generates step-by-step mitigation roadmaps
- **PDF Report Generation:** Creates professional vulnerability assessment reports
- **Conversational Interface:** Natural language interaction with context memory

---

## Features

### 1) Multi-Agent Architecture
Patch Path is composed of specialized agents coordinated by a planner:
- **Planner Agent:** Orchestrates all agents and maintains conversation context
- **Tech Stack Detection Agent:** Extracts technologies from architecture images
- **CVE Search Agent:** Searches the vulnerability database using semantic similarity
- **Risk Assessment Agent:** Evaluates CVEs using CVSS and EPSS scores
- **Risk Mitigation Agent:** Produces actionable mitigation strategies
- **Report Generation Agent:** Builds downloadable PDF reports with clean formatting

### 2) Dual Memory System
- **Image Context:** Stores tech stack + extracted details from image uploads
- **Text Context:** Maintains context from text-based queries
- **Auto context switching** based on user input type (image vs text)

### 3) Advanced CVE Search
- Keyword matching across CVE fields (title/description/combined text)
- Vector similarity search (cosine similarity)
- Handles multi-word technologies (e.g., “Apache Kafka”, “Google Cloud”)
- Direct CVE-ID lookup
- Configurable similarity threshold (default: **0.55**)
- Ranks results (Top **15**)

### 4) Intelligent Intent Detection
- LLM-based query understanding with keyword fallback
- Context-aware routing to the right agent
- Handles follow-ups naturally
- Filters out non-cybersecurity queries with a helpful message

### 5) Modern Web Interface
- React frontend with responsive UI
- Real-time agent animation during processing
- Markdown rendering for formatted output
- Image upload support
- PDF report download button

---

## Architecture

### System Flow (High Level)
```text
User Input (Text/Image)
        ↓
Planner Agent (Orchestrator)
        ↓
Intent Detection & Context Management
        ↓
Specialized Agent Routing
  ├─ Tech Stack Detection Agent
  ├─ CVE Search Agent
  ├─ Risk Assessment Agent
  ├─ Risk Mitigation Agent
  └─ Report Generation Agent
        ↓
Agent Processing
        ↓
Context Update (Memory)
        ↓
Formatted Response
        ↓
Frontend Display
```
## Data Flow

### Image Upload Flow

- Image → Planner → Tech Stack Detection → Extract Technologies → Store in Image Context

### CVE Search Flow

- Query → Planner → CVE Search → RAG Pipeline → Vector Search → Snowflake DB → Results

### Risk Assessment Flow

- Query + CVEs from Context → Planner → Risk Assessment → Calculate Risk Scores → Generate Table

### Mitigation Flow

- Query + CVE IDs → Planner → Risk Mitigation → Generate Steps → Trigger Report Generation

##RAG Pipeline Search Path
```text
User Query
  ↓
Query Intent Parsing (extract technologies, semantic query)
  ↓
Keyword Matching (LIKE queries on TITLE, DESCRIPTION, COMBINED_TEXT)
  ↓
Vector Embedding (Snowflake EMBED_TEXT_1024)
  ↓
Cosine Similarity Search (VECTOR_COSINE_SIMILARITY)
  ↓
Filter by Similarity Threshold (≥ 0.55)
  ↓
Rank by Similarity Score (Top 15)
  ↓
LLM Generation (context-aware answer)
  ↓
Formatted Response
```

## Installation
### Prerequisites

- Python: 3.8+
- Node.js: 16+
- npm: comes with Node.js
- Snowflake Account: for CVE database access + vector search
- OpenAI API Key: for LLM/vision functionality


## Step 1 — Clone the Repository
```text
git clone <repository-url>
cd FULL-FINAL-CVE
```
## Step 2 — Install Python Dependencies
```text
pip install -r requirements.txt
```

## Step 3 — Install React Dependencies
```text
cd frontend
npm install
cd ..
```
## Project Structure
```text
FULL-FINAL-CVE/
├── Agents/                          # Specialized AI agents
│   ├── __init__.py
│   ├── Planner.py                   # Main orchestrator agent
│   ├── image_reading_agent.py       # Tech stack detection from images
│   ├── cve_search_agent.py          # CVE search functionality
│   ├── risk_assessment_agent.py     # Risk calculation and assessment
│   ├── risk_mitigation_agent.py     # Mitigation plan generation
│   └── report_generation_agent.py   # PDF report generation
│
├── RAG_PIPELINE/                    # Retrieval-Augmented Generation
│   ├── Rag_Pipeline.py              # Main RAG orchestration
│   ├── Rag_generation.py            # LLM answer generation
│   ├── vector_search.py             # Vector similarity search
│   ├── generate_embeddings.py       # Embedding generation utilities
│   └── verify_embeddings.py         # Embedding verification
│
├── patchpath/                       # Configuration and utilities
│   ├── config/
│   │   ├── __init__.py
│   │   └── snowflake_config.py      # Snowflake connection config
│   └── agents/                      # Legacy agent code (if any)
│
├── frontend/                        # React.js frontend
│   ├── public/
│   │   └── index.html
│   ├── src/
│   │   ├── App.js                   # Main React component
│   │   ├── App.css                  # Main styles
│   │   ├── index.js                 # React entry point
│   │   └── components/
│   │       ├── ChatInterface.js     # Chat UI component
│   │       ├── AgentAnimation.js    # Loading animation
│   │       ├── Header.js            # Header component
│   │       └── Sidebar.js           # Sidebar component
│   ├── package.json                 # React dependencies
│   └── .gitignore
│
├── Config_files/                    # Configuration files
│   └── __init__.py
│
├── Test_Scripts/                    # Test utilities
│   ├── test_vector_search.py
│   └── test_Vuln_data.py
│
├── api_server.py                    # Flask backend API server
├── main.py                          # Alternative entry point
├── requirements.txt                 # Python dependencies
├── .gitignore                       # Git ignore rules
├── QUICK_START.md                   # Quick start guide
├── README_FRONTEND.md               # Frontend documentation
├── Patch-path-logo.png              # Project logo
└── .env                             # Environment variables (not in git)
```

## System Architecture
<img width="2430" height="770" alt="image" src="https://github.com/user-attachments/assets/66c8cdda-6b3b-4f88-ad8f-0bd07be7d662" />


## Technologies Used
### Backend

## Backend Tech Stack

<p align="left">
  <img alt="Apache Airflow" src="https://img.shields.io/badge/Apache%20Airflow-017CEE?style=for-the-badge&logo=apacheairflow&logoColor=white" />
  <img alt="Snowflake" src="https://img.shields.io/badge/Snowflake-29B5E8?style=for-the-badge&logo=snowflake&logoColor=white" />
  <img alt="Snowflake Cortex" src="https://img.shields.io/badge/Snowflake%20Cortex-29B5E8?style=for-the-badge&logo=snowflake&logoColor=white" />
  <img alt="Amazon S3" src="https://img.shields.io/badge/Amazon%20S3-569A31?style=for-the-badge&logo=amazons3&logoColor=white" />
  <img alt="Apache Parquet" src="https://img.shields.io/badge/Apache%20Parquet-50A2D4?style=for-the-badge&logo=apacheparquet&logoColor=white" />
  <img alt="SQL" src="https://img.shields.io/badge/SQL-336791?style=for-the-badge&logo=postgresql&logoColor=white" />
  <img alt="LangChain" src="https://img.shields.io/badge/LangChain-ffffff?style=for-the-badge&logo=langchain&logoColor=0FA958" />
  <img alt="OpenAI" src="https://img.shields.io/badge/OpenAI-93f6ef?style=for-the-badge&logo=openai&logoColor=black" />
</p>

### Frontend

<p align="left">
  <img alt="React" src="https://img.shields.io/badge/React%2018-61DAFB?style=for-the-badge&logo=react&logoColor=black" />
  <img alt="Flask" src="https://img.shields.io/badge/Flask-000000?style=for-the-badge&logo=flask&logoColor=white" />
</p>

