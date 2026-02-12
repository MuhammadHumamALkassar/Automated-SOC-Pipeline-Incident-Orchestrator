# SOAR-EDR Automated Security Pipeline

## Project Overview
This project is a fully automated Security Orchestration, Automation, and Response (SOAR) pipeline designed to simulate, detect, and respond to SSH brute-force attacks in real-time.

By integrating Splunk for detection, Python for orchestration, and VirusTotal for threat intelligence, this pipeline reduces the "Mean Time to Respond" (MTTR) from minutes to seconds. It automatically classifies threats and notifies the SOC team via Discord with enriched incident data.

## Architecture and Data Flow
The pipeline follows a "Detect -> Enrich -> Respond" workflow:

1.  **Ingestion:** A custom Python script generates authentic SSH brute-force logs and sends them to Splunk via TCP (Port 1514).
2.  **Detection:** Splunk analyzes the stream in real-time, identifying high-velocity login failures using statistical thresholding (SPL).
3.  **Orchestration:** A Splunk Webhook forwards the alert payload to a custom Flask listener running on the host machine.
4.  **Enrichment:** The system extracts the attacker's IP and queries the VirusTotal API to retrieve a reputation score.
5.  **Response:** The system formats a professional incident card (color-coded by severity) and pushes it to a private Discord channel.



## Key Features
* **Infrastructure as Code:** Splunk Enterprise deployed via Docker Compose with persistent volumes.
* **Behavioral Detection:** Custom SPL query triggers only on statistical anomalies (threshold > 10 failures), ignoring isolated errors.
* **Automated Enrichment:** Dynamic API lookup for every alert to determine if the IP is a known global threat.
* **Real-time Response:** Zero-touch notification system using Webhooks to alert analysts immediately.

## Technology Stack
* **SIEM:** Splunk Enterprise (Dockerized)
* **Orchestration:** Python 3 (Flask, Requests)
* **Threat Intelligence:** VirusTotal v3 API
* **Alerting:** Discord Webhooks

---

## Installation and Setup

### 1. Prerequisites
* Docker Desktop installed.
* Python 3.x installed.
* A VirusTotal API Key (Free tier).
* A Discord Webhook URL.

### 2. Infrastructure Setup (Docker)
Initialize the Splunk environment using the docker-compose configuration.

1.  Create a project directory named `soc_pipeline`.
2.  Create a `docker-compose.yml` file with the following port mappings:
    * 8000: Splunk Web Interface
    * 8089: Management Port
    * 1514: Custom TCP Input for Logs.
3.  Start the container:
    ```bash
    docker-compose up -d
    ```

### 3. Orchestrator Configuration
Create a virtual environment and install dependencies to keep the host clean.

```bash
# Create and activate virtual environment (Windows)
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install required libraries
pip install flask requests python-dotenv