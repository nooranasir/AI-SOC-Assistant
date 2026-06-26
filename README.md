# AI SOC Assistant

An intelligent, type-safe security operations center (SOC) copilot designed to analyze alerts, map threat tactics using MITRE ATT&CK, enrich indicators of compromise (IOCs) with external threat intelligence, generate interactive playbook responses using LLMs, and produce comprehensive incident reports.

---

## Project Overview

AI SOC Assistant acts as a virtual tier-1 analyst. It digests raw alert logs from diverse security platforms (such as Wazuh, Windows Event Logs, Sysmon, and LetsDefend), extracts critical indicators (IPs, domains, hashes, and URLs), queries VirusTotal to determine reputation, maps alerts to standardized MITRE ATT&CK techniques, and generates actionable, step-by-step containment and mitigation playbooks powered by LLMs (Groq / Llama 3).

---

## Architecture

The project follows a clean, decoupled service architecture:

```mermaid
graph TD
    subgraph Frontend (React SPA)
        UI[Vite + React Dashboard]
    end

    subgraph Backend (FastAPI Services)
        API[FastAPI Router]
        Parser[Alert Parser]
        Mitre[MITRE ATT&CK Mapper]
        Extractor[IOC Extractor]
        VT[VirusTotal Service]
        Abuse[AbuseIPDB Service - Offline Mock]
        ES[Elasticsearch Service - Offline Mock]
        AI[AI Alert Analysis Service]
        Invest[Investigation Service]
        Report[Incident Report Generator]
    end

    subgraph External APIs & Storage
        Groq[Groq Llama 3 API]
        VT_API[VirusTotal v3 API]
        Local_JSON[mitre_mapping.json]
    end

    UI -->|JSON HTTP Request| API
    API --> Parser
    API --> Mitre
    API --> Extractor
    API --> VT
    API --> AI
    API --> Invest
    API --> Report

    Mitre -->|Reads| Local_JSON
    VT -->|IP/Domain/URL/Hash Lookups| VT_API
    AI -->|System/User Prompt| Groq
    Invest -->|Playbook Prompts| Groq
```

---

## Features

- **Multi-Format Log Parser**: Seamlessly normalizes logs from Windows Security Auditing, Sysmon, Wazuh alerts, LetsDefend training alerts, and generic SIEM JSON schemas.
- **MITRE ATT&CK Mapping**: Performs automated local keywords and semantic mapping against a curated local database of MITRE ATT&CK techniques.
- **Threat Intelligence Enrichment**: Perform live, secure lookups for IPs, domains, URLs, and file hashes using the VirusTotal v3 API. Degrades gracefully if credentials are not configured or are rate-limited.
- **AI-Powered Threat Analysis & Playbooks**: Generates plain-English descriptions of alerts, maps tactics, and drafts immediate mitigation/containment checklists using Groq's Llama 3 model.
- **Incident Report Generation**: Auto-generates standardized markdown and PDF-ready Incident Reports summarizing detections, timeline of actions, and MITRE context.
- **Interactive SOC Dashboard**: Beautiful dark-mode dashboard with real-time connection badges (`🟢 Connected`, `🟡 Not Configured`, `⚫ Offline`) and rich telemetry tables.

---

## Tech Stack

### Backend
- **Core**: Python 3.12, FastAPI
- **LLM/Client Integration**: Groq API, OpenAI SDK, Tenacity (exponential backoff & retries)
- **Validation**: Pydantic v2
- **Networking**: Requests, HTTPX
- **Server**: Uvicorn

### Frontend
- **Framework**: React 18, TypeScript, Vite
- **Styling**: Vanilla CSS (sleek dark mode design, hover micro-animations, glassmorphism)
- **Routing & State**: React Hooks, Context API

---

## Folder Structure

```text
AI-SOC-Assistant/
├── app/                      # Backend FastAPI codebase
│   ├── api/                  # API endpoints and middleware routers
│   ├── core/                 # Configuration and settings loader
│   ├── schemas/              # Pydantic request/response models
│   └── services/             # Core business logic (AI, parsing, reports, intelligence)
├── data/
│   └── mitre/                # MITRE technique mappings database (JSON)
├── frontend/                 # React SPA frontend code
│   ├── src/
│   │   ├── components/       # Reusable React UI controls (badges, tables, panels)
│   │   ├── context/          # Shared workspace state management
│   │   ├── pages/            # Core views (dashboard, upload, intelligence)
│   │   └── services/         # API HTTP client configurations
│   ├── index.html
│   └── package.json
├── logs/                     # Local diagnostic logs and sample alerts
│   └── samples/              # Starter logs (sshd, wazuh, windows events, sysmon)
├── prompts/                  # Markdown system prompts for LLM analyses
├── reports/                  # Generated Incident Reports folder (Markdown)
├── .env.example              # Placeholder environment variables file
├── .gitignore                # Production release file exclusions list
├── README.md                 # Project documentation
└── requirements.txt          # Python packages manifest
```

---

## Installation

### Prerequisites
- **Python**: Version 3.12 or higher.
- **Node.js**: Version 20.x, 22.x or higher (npm included).

---

## Backend Setup

1. Navigate to the project root and create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. Install python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Setup environment variables:
   ```bash
   cp .env.example .env
   ```
   Open the `.env` file and insert your API keys:
   - **GROQ_API_KEY**: Get a free API key from [Groq Console](https://console.groq.com/).
   - **VIRUSTOTAL_API_KEY**: Retrieve your key from your [VirusTotal Account](https://www.virustotal.com/).

4. Start the backend developer server:
   ```bash
   uvicorn app.main:app --reload
   ```
   The API will start at `http://127.0.0.1:8000`. You can access interactive OpenAPI docs at `http://127.0.0.1:8000/docs`.

---

## Frontend Setup

1. Navigate to the frontend directory:
   ```bash
   cd frontend
   ```

2. Install node dependencies:
   ```bash
   npm install
   ```

3. Setup environment configuration:
   ```bash
   cp .env.example .env
   ```

4. Start the frontend developer server:
   ```bash
   npm run dev
   ```
   Open your browser to `http://localhost:5173`.

---

## Environment Variables

| Variable | Description | Example / Default | Required |
| :--- | :--- | :--- | :--- |
| `APP_NAME` | Name of the FastAPI application | `"AI SOC Assistant"` | No |
| `APP_VERSION` | Current platform version | `1.0.0` | No |
| `APP_ENV` | Development or production state | `development` | No |
| `LLM_PROVIDER` | LLM service provider adapter | `groq` | Yes |
| `GROQ_API_KEY` | Groq platform authorization API key | `gsk_...` | Yes |
| `GROQ_MODEL` | Default model used for playbooks | `llama-3.3-70b-versatile` | Yes |
| `VIRUSTOTAL_API_KEY`| Live threat lookup API key | `a6593c...` | No (Degrades to Not Configured) |
| `VIRUSTOTAL_BASE_URL`| VirusTotal REST v3 root URL | `https://www.virustotal.com/api/v3` | No |
| `MITRE_MAPPING_PATH`| Path to local ATT&CK database | `data/mitre/mitre_mapping.json` | No |

---

## API Endpoints

- **`GET /health`**: Heartbeat route checking system health.
- **`POST /alerts/parse`**: Parse and normalize raw logs into standardized structures.
- **`POST /alerts/analyze`**: Run AI security alert analysis.
- **`POST /alerts/investigate`**: Generate interactive playbooks and extract IOC context.
- **`POST /mitre/map`**: Map alert details to standard local MITRE ATT&CK techniques.
- **`POST /reports/incidents`**: Compile comprehensive markdown incident reports.
- **`POST /virustotal/lookup`**: Trigger a live reputation lookup for any security indicator.

---

## Workflow

1. **Ingestion**: Paste raw JSON alerts or upload log files (Wazuh, Sysmon, Windows Security Auditing) on the **Upload Alert** page.
2. **Parsing & Mapping**: The system automatically determines the log source format, normalizes metadata, and maps the event to a matching MITRE ATT&CK technique locally.
3. **Enrichment**: Extracted indicators (IPs, URLs, domains, hashes) are queried live on VirusTotal, yielding detection ratios and community reputation scores.
4. **AI Playbooks**: The core LLM analyzes the alert and threat intelligence context to generate playbooks (containment actions, recovery steps, and confidence scores).
5. **Reporting**: Click **Generate Incident Report** to save a complete, audit-ready Markdown document to the local `reports/` folder.

---

## Screenshots

*(Hover effects, live badges, and playbooks in dark mode theme)*

1. **Dashboard Home**: Real-time alert feed, threat intelligence summaries, and telemetry widgets.
2. **Threat Intelligence Page**: Indicator queries with detection stats, reputation metrics, and links to VirusTotal GUI reports.

---

## Future Improvements

- **Splunk & Wazuh API Integrations**: Directly fetch alerts and ingest logs from running SIEM servers using webhooks.
- **Active Containment Actions**: Implement automated remediation scripts (e.g. active blocking of threat IPs on firewalls, host isolation via EDR integrations).
- **Persistent Database Cache**: Store analyzed alerts, playbook logs, and incident history in a PostgreSQL or MongoDB database instead of in-memory context state.

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
