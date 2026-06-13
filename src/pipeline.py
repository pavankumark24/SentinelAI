# src/pipeline.py

import os
import hashlib
import requests
import concurrent.futures
import streamlit as st
from email import message_from_bytes
from src.predict import predict_email, get_threat_indicators
from src.url_analyzer import extract_urls, analyze_url, get_final_destination
from src.virustotal import check_url_virustotal
from src.sender_reputation import analyze_sender
from src.threat_engine import calculate_threat_score
from src.explainability import explain_score
from src.recommendations import get_recommendation
from src.report_generator import generate_report
from src.header_analyzer import parse_and_audit_headers

def process_single_url(url: str) -> dict:
    """
    Isolated processing unit for concurrent execution across discovered URLs.
    """
    try:
        real_url = get_final_destination(url)
        analysis = analyze_url(real_url)
        return {
            "shortened_url": url,
            "final_destination": real_url,
            "domain": analysis.get("domain", "Unknown"),
            "score": analysis.get("score", 0),
            "findings": list(dict.fromkeys(analysis.get("findings", [])))
        }
    except Exception as e:
        return {
            "shortened_url": url,
            "final_destination": url,
            "domain": "Resolution Error",
            "score": 15,
            "findings": [f"System could not trace path: {str(e)}"]
        }

def run_sentinel_pipeline(text: str, input_type: str, mode: str, attachment_bytes: bytes = None, attachment_name: str = None) -> dict:
    """
    Orchestrates the complete threat analysis lifecycle for SentinelAI.
    Utilizes concurrency for external scanning and aggregates destination telemetry to prevent UI repetition.
    """
    # 1. Linguistic Model Execution & Heuristic Feature Mapping
    prediction, confidence = predict_email(text)
    confidence_percent = round(confidence * 100, 2)
    
    # Deduplicate raw structural text indicators right away
    indicators = list(dict.fromkeys(get_threat_indicators(text)))
    sender_result = analyze_sender(text)
    if sender_result and "findings" in sender_result:
        sender_result["findings"] = list(dict.fromkeys(sender_result["findings"]))
    
    # 2. Asynchronous URL Intelligence Routing
    raw_urls = extract_urls(text)
    unique_urls = list(dict.fromkeys(raw_urls))
    url_results = []
    url_score = 0
    
    if unique_urls:
        # Use concurrent threads to speed up domain network resolution checks
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(5, len(unique_urls))) as executor:
            raw_url_results = list(executor.map(process_single_url, unique_urls))
        
        # CRITICAL FIX: Deduplicate based on final target domain to prevent UI flooding from tracking links
        seen_domains = set()
        for item in raw_url_results:
            domain_key = item["domain"].lower().strip()
            if domain_key not in seen_domains:
                seen_domains.add(domain_key)
                url_results.append(item)
                
        if url_results:
            url_score = max(item["score"] for item in url_results)
        
    # 3. Dynamic Protocol Header Auditing
    header_score = 0
    header_results = None
    if input_type == "Raw Email Source (Headers Included)":
        header_results = parse_and_audit_headers(text)
        if header_results and "findings" in header_results:
            header_results["findings"] = list(dict.fromkeys(header_results["findings"]))
        header_score = header_results.get("spoof_risk", 0) if header_results else 0
        
    # 4. Standalone or Injected Attachment Sandbox Check
    attachment_results = None
    attachment_score = 0
    if attachment_bytes:
        sha256_hash = hashlib.sha256(attachment_bytes).hexdigest()
        attachment_results = {
            "filename": attachment_name if attachment_name else "unknown_payload.bin",
            "sha256": sha256_hash,
            "status": "Clean / Not Listed in Malicious Repositories",
            "malicious_count": 0,
            "score": 0
        }
        
        if mode == "Online":
            vt_api_key = os.environ.get("VT_API_KEY", "")
            if vt_api_key:
                try:
                    vt_file_url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
                    headers = {"x-apikey": vt_api_key}
                    response = requests.get(vt_file_url, headers=headers, timeout=6)
                    if response.status_code == 200:
                        data = response.json()
                        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                        malicious = stats.get("malicious", 0)
                        suspicious = stats.get("suspicious", 0)
                        
                        total_flags = malicious + suspicious
                        attachment_results["malicious_count"] = total_flags
                        if total_flags > 0:
                            attachment_results["status"] = f"🚨 MATCHED MALICIOUS ARTIFACT ({total_flags} Engine Flags)"
                            attachment_score = min((malicious * 30) + (suspicious * 15), 100)
                            attachment_results["score"] = attachment_score
                except Exception:
                    attachment_results["status"] = "Intel Engine Endpoint Timeout"

    # 5. Domain Aggregation Threat Intel (VirusTotal Integration)
    vt_score = 0
    vt_result = None
    if mode == "Online" and url_results:
        try:
            vt_result = check_url_virustotal(url_results[0]["shortened_url"])
            if vt_result:
                malicious = vt_result.get("malicious", 0)
                suspicious = vt_result.get("suspicious", 0)
                vt_score = min((malicious * 20) + (suspicious * 10), 100)
        except Exception:
            pass

    # 6. Consolidated Risk Score Calculation
    overall_score = calculate_threat_score(
        ml_score=confidence_percent,
        url_score=url_score,
        sender_score=sender_result.get("score", 0),
        vt_score=vt_score,
        header_score=header_score
    )
    
    if attachment_score > 0:
        overall_score = max(overall_score, attachment_score)
    
    if overall_score < 20:
        threat_level = "INFORMATIONAL"
    elif overall_score < 40:
        threat_level = "LOW"
    elif overall_score < 70:
        threat_level = "MEDIUM"
    elif overall_score < 90:
        threat_level = "HIGH"
    else:
        threat_level = "CRITICAL"

    # 7. Document Output Generation
    display_confidence = confidence_percent if prediction == 1 else round(100 - confidence_percent, 2)
    explanation = explain_score(confidence_percent, url_score, sender_result.get("score", 0), vt_score)
    
    raw_url_reports = [
        {"domain": item["domain"], "score": item["score"], "findings": item["findings"]} 
        for item in url_results
    ]
    
    generated_md_report = generate_report(
        "PHISHING" if (prediction == 1 or overall_score >= 70) else "SAFE",
        display_confidence,
        threat_level,
        indicators,
        raw_url_reports
    )

    return {
        "prediction": 1 if (prediction == 1 or overall_score >= 70) else 0,
        "display_confidence": display_confidence,
        "confidence_percent": confidence_percent,
        "overall_score": overall_score,
        "threat_level": threat_level,
        "indicators": indicators,
        "sender_result": sender_result,
        "header_results": header_results,
        "url_results": url_results,
        "vt_result": vt_result,
        "attachment_results": attachment_results,
        "explanation": explanation,
        "header_score": header_score,
        "report": generated_md_report
    }