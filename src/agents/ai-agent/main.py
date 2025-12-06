import os
import json
import logging
import re
import threading
import time
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
import requests
import google.generativeai as genai

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

OPENSEARCH_URL = os.getenv("OPENSEARCH_URL", "http://opensearch:9200")
OPENSEARCH_INDEX = os.getenv("OPENSEARCH_INDEX")
GOOGLE_CHAT_WEBHOOK = os.getenv("GOOGLE_CHAT_WEBHOOK")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash-lite")

# Log scanning configuration
LOG_SCAN_INTERVAL = int(os.getenv("LOG_SCAN_INTERVAL", "30"))  # seconds (default: 5 minutes)
LOG_SCAN_ENABLED = os.getenv("LOG_SCAN_ENABLED", "true").lower() == "true"
ERROR_PATTERNS = [
    r"(?i)(error|exception|failed|failure|fatal|panic|critical)",
    r"(?i)(connection.*refused|connection.*timeout|cannot connect)",
    r"(?i)(database.*error|db.*error|sql.*error)",
    r"(?i)(out of memory|oom|memory.*exhausted)",
    r"(?i)(timeout|timed out|deadline exceeded)"
]

# Configure Gemini if API key is available
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)

# Simple OpenSearch query to fetch recent logs for a service or instance
def query_opensearch(service=None, instance=None, minutes=5, size=50):
    now = datetime.utcnow()
    start = (now - timedelta(minutes=minutes)).isoformat() + 'Z'
    must = []
    
    # Try to extract service name from instance if not explicitly provided
    if not service and instance:
        # instance might be like "product-catalog:8080" or "localhost:9100"
        service_candidate = instance.split(":")[0]
        # Only use it if it looks like a real service name (not localhost or IP)
        if service_candidate not in ["localhost", "127.0.0.1"] and not service_candidate.replace(".", "").isdigit():
            service = service_candidate
    
    if service:
        must.append({"match": {"resource.service.name": service}})
    if instance:
        # Try matching the instance name if it looks like a hostname
        instance_name = instance.split(":")[0] if ":" in instance else instance
        must.append({"match": {"host.name": instance_name}})
    body = {
        "query": {
            "bool": {
                "must": must if must else [{"match_all": {}}],
                "filter": [{"range": {"@timestamp": {"gte": start}}}]
            }
        },
        "size": size,
        "sort": [{"@timestamp": {"order": "desc"}}]
    }
    try:
        # Use a configured index pattern if provided, otherwise search all indices
        if OPENSEARCH_INDEX:
            url = f"{OPENSEARCH_URL}/{OPENSEARCH_INDEX}/_search"
        else:
            url = f"{OPENSEARCH_URL}/_search"
        r = requests.post(url, json=body, timeout=15)
        if r.status_code >= 400:
            # Log response body to help debug 400 errors
            logging.error("OpenSearch returned %s: %s", r.status_code, r.text)
            r.raise_for_status()
        hits = r.json().get("hits", {}).get("hits", [])
        logs = []
        for h in hits:
            src = h.get("_source", {})
            ts = src.get("@timestamp") or h.get("_source", {}).get("timestamp")
            message = src.get("body") or src.get("message") or json.dumps(src)
            logs.append({"ts": ts, "message": message})
        return logs
    except requests.exceptions.HTTPError as e:
        logging.exception("OpenSearch query HTTP error: %s", e)
        # Try a simpler time-range-only query as a fallback to diagnose mapping/index issues
        try:
            simple_body = {
                "query": {"range": {"@timestamp": {"gte": start}}},
                "size": size,
                "sort": [{"@timestamp": {"order": "desc"}}]
            }
            logging.info("Retrying OpenSearch with a simpler query against %s", url)
            r2 = requests.post(url, json=simple_body, timeout=15)
            if r2.status_code >= 400:
                logging.error("Fallback OpenSearch query failed %s: %s", r2.status_code, r2.text)
                # Also fetch indices list to help debug
                try:
                    idx = requests.get(f"{OPENSEARCH_URL}/_cat/indices?format=json", timeout=10)
                    logging.error("OpenSearch indices: %s", idx.text)
                except Exception:
                    logging.exception("Failed to list OpenSearch indices")
                return []
            hits = r2.json().get("hits", {}).get("hits", [])
            logs = []
            for h in hits:
                src = h.get("_source", {})
                ts = src.get("@timestamp") or src.get("timestamp")
                message = src.get("body") or src.get("message") or json.dumps(src)
                logs.append({"ts": ts, "message": message})
            return logs
        except Exception:
            logging.exception("Fallback OpenSearch query failed")
            return []
    except Exception as e:
        logging.exception("OpenSearch query failed: %s", e)
        return []

# Minimal LLM caller (Gemini API). If not configured, fallback to simple summarizer.
def summarize_with_llm(prompt):
    if GEMINI_API_KEY:
        try:
            model = genai.GenerativeModel(GEMINI_MODEL)
            response = model.generate_content(
                prompt,
                generation_config=genai.types.GenerationConfig(
                    max_output_tokens=400,
                    temperature=0.1,
                )
            )
            return response.text if response and hasattr(response, 'text') else "(no summary returned)"
        except Exception as e:
            logging.exception("Gemini API call failed: %s", e)
            # fallthrough to simple
    # simple fallback: return first few lines of the prompt (which includes logs)
    try:
        lines = prompt.splitlines()
        return "\n".join(lines[:15]) or "(no logs to summarize)"
    except Exception:
        return "(no logs to summarize)"

def post_to_google_chat(text):
    if not GOOGLE_CHAT_WEBHOOK:
        logging.info("No GOOGLE_CHAT_WEBHOOK configured; would have posted:\n%s", text)
        return False
    try:
        payload = {"text": text}
        r = requests.post(GOOGLE_CHAT_WEBHOOK, json=payload, timeout=10)
        r.raise_for_status()
        return True
    except Exception as e:
        logging.exception("Failed to post to Google Chat: %s", e)
        return False

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})

@app.route("/webhook", methods=["POST"])
def webhook():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "invalid json"}), 400
    alerts = data.get("alerts") or []
    results = []
    for a in alerts:
        labels = a.get("labels", {})
        annotations = a.get("annotations", {})
        alertname = labels.get("alertname") or labels.get("alert")
        service = labels.get("service") or labels.get("job") or labels.get("kubernetes_namespace")
        instance = labels.get("instance") or labels.get("host") or labels.get("instance_name")
        logging.info("Processing alert %s for service=%s instance=%s", alertname, service, instance)
        logs = query_opensearch(service=service, instance=instance, minutes=10, size=50)
        log_text = "\n".join([f"{l.get('ts')}: {l.get('message')}" for l in logs[:50]])
        prompt = f"Alert: {alertname}\nLabels: {json.dumps(labels)}\nAnnotations: {json.dumps(annotations)}\n\nRecent logs:\n{log_text}\n\nPlease summarize probable causes and suggestions." 
        summary = summarize_with_llm(prompt)
        message = f"AI Assistant — Alert {alertname}\n\nSummary:\n{summary}\n\n(Logs sample attached below)\n{log_text[:3000]}"
        posted = post_to_google_chat(message)
        results.append({"alert": alertname, "posted": posted})
    return jsonify({"results": results}), 200

# Scan logs for errors automatically
def scan_logs_for_errors():
    """Background task to scan OpenSearch logs for error patterns"""
    logging.info("Log scanner started (interval: %ds)", LOG_SCAN_INTERVAL)
    last_check = datetime.utcnow() - timedelta(minutes=5)
    
    while True:
        try:
            time.sleep(LOG_SCAN_INTERVAL)
            now = datetime.utcnow()
            start = last_check.isoformat() + 'Z'
            
            # Query for recent logs with error keywords
            body = {
                "query": {
                    "bool": {
                        "must": {
                            "query_string": {
                                "query": "error OR exception OR failed OR fatal OR panic OR critical",
                                "fields": ["body", "message"]
                            }
                        },
                        "filter": [{"range": {"@timestamp": {"gte": start}}}]
                    }
                },
                "size": 50,
                "sort": [{"@timestamp": {"order": "desc"}}]
            }
            
            url = f"{OPENSEARCH_URL}/{OPENSEARCH_INDEX}/_search" if OPENSEARCH_INDEX else f"{OPENSEARCH_URL}/_search"
            r = requests.post(url, json=body, timeout=15)
            
            if r.status_code == 200:
                hits = r.json().get("hits", {}).get("hits", [])
                
                if hits:
                    # Group errors by service
                    errors_by_service = {}
                    for h in hits:
                        src = h.get("_source", {})
                        service = src.get("resource", {}).get("service.name", "unknown")
                        body_text = src.get("body") or src.get("message", "")
                        timestamp = src.get("@timestamp")
                        
                        # Check if message matches error patterns
                        for pattern in ERROR_PATTERNS:
                            if re.search(pattern, body_text):
                                if service not in errors_by_service:
                                    errors_by_service[service] = []
                                errors_by_service[service].append({
                                    "timestamp": timestamp,
                                    "message": body_text[:200]
                                })
                                break
                    
                    # Report errors found
                    for service, errors in errors_by_service.items():
                        if len(errors) >= 3:  # Only alert if 3+ errors from same service
                            error_summary = "\n".join([f"[{e['timestamp']}] {e['message']}" for e in errors[:10]])
                            prompt = f"Service: {service}\n\nDetected {len(errors)} errors in logs:\n{error_summary}\n\nPlease analyze and suggest root cause."
                            summary = summarize_with_llm(prompt)
                            message = f"🚨 AI Agent - Auto-detected Errors\n\nService: {service}\nErrors: {len(errors)}\n\nAnalysis:\n{summary}\n\nRecent errors:\n{error_summary[:1000]}"
                            post_to_google_chat(message)
                            logging.info("Auto-detected %d errors in service %s", len(errors), service)
            
            last_check = now
            
        except Exception as e:
            logging.exception("Error in log scanner: %s", e)
            time.sleep(60)  # Wait 1 minute before retry on error

if __name__ == "__main__":
    # Start background log scanner if enabled
    if LOG_SCAN_ENABLED:
        scanner_thread = threading.Thread(target=scan_logs_for_errors, daemon=True)
        scanner_thread.start()
    
    port = int(os.getenv("AI_AGENT_PORT", "4000"))
    app.run(host="0.0.0.0", port=port)
