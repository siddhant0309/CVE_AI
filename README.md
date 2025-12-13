# Patch Path — AI-Powered Cybersecurity Vulnerability Management System

Patch Path is an AI-powered cybersecurity vulnerability management system that helps organizations identify, assess, and mitigate **Common Vulnerabilities and Exposures (CVEs)** across their technology stack. It uses a **multi-agent architecture** to deliver end-to-end vulnerability analysis, risk scoring, and step-by-step mitigation plans—plus downloadable **PDF reports**.

> **Tagline:** *Find the path to your patch.*

---

## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [API Endpoints](#api-endpoints)
- [Project Structure](#project-structure)
- [Technologies Used](#technologies-used)
- [Troubleshooting](#troubleshooting)
- [Team](#team)

---

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
Data Flow

Image Upload Flow

Image → Planner → Tech Stack Detection → Extract Technologies → Store in Image Context

CVE Search Flow

Query → Planner → CVE Search → RAG Pipeline → Vector Search → Snowflake DB → Results

Risk Assessment Flow

Query + CVEs from Context → Planner → Risk Assessment → Calculate Risk Scores → Generate Table

Mitigation Flow

Query + CVE IDs → Planner → Risk Mitigation → Generate Steps → Trigger Report Generation

RAG Pipeline (Search Path)



