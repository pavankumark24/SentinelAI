# app.py

import streamlit as st
import plotly.graph_objects as go
from email import message_from_bytes
from src.pipeline import run_sentinel_pipeline
from src.ocr import extract_text
from src.recommendations import get_recommendation

st.set_page_config(
    page_title="SentinelAI Workspace",
    page_icon="🛡️",
    layout="wide"
)

# --- SIDEBAR CONTROL PANEL ---
st.sidebar.title("🛡️ SentinelAI Core")
mode = st.sidebar.radio("Analysis Mode Network Layer", ["Offline", "Online"])
st.sidebar.divider()
st.sidebar.info(f"🟢 Processing Unit Engaged\nThreat Intel Sync: **{mode} Mode**")

st.title("🛡️ SentinelAI")
st.subheader("Enterprise Counter-Phishing & Payload Assessment Platform")

tab1, tab2, tab3 = st.tabs([
    "📧 Email Core Analysis",
    "📸 Graphic OCR Intake",
    "📁 Advanced Object Sandbox"
])

# --- METROLOGY DASHBOARD RENDER COMPONENT ---
def render_dashboard(payload: dict, show_headers: bool):
    """
    Renders centralized diagnostics, telemetry visual gauges, and clean, deduplicated report segments.
    """
    st.write("")
    if payload["prediction"] == 1:
        st.error("🚨 HIGH-RISK THREAT ALERT: PHISHING INDICATORS IDENTIFIED")
    else:
        st.success("✅ ANALYSIS COMPLETE: SIGNATURES COHERENT WITH SAFE COMMS")

    col1, col2 = st.columns([1.8, 1.2])
    
    with col1:
        st.write("")
        st.write("")
        st.metric("Linguistic Model Prediction Confidence", f"{payload['display_confidence']}%")
        st.metric("System Operational Risk Level", payload['threat_level'])
        
    with col2:
        score_value = float(payload["overall_score"])
        gauge_color = "green" if score_value < 40 else "orange" if score_value < 70 else "red"
        
        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=score_value,
            domain={'x': [0, 1], 'y': [0, 1]},
            title={'text': "Aggregated Threat Index", 'font': {'size': 16, 'color': 'white'}},
            gauge={
                'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': "white"},
                'bar': {'color': gauge_color},
                'bgcolor': "rgba(0,0,0,0)",
                'borderwidth': 1,
                'bordercolor': "gray",
                'steps': [
                    {'range': [0, 40], 'color': 'rgba(0, 255, 0, 0.05)'},
                    {'range': [40, 70], 'color': 'rgba(255, 165, 0, 0.05)'},
                    {'range': [70, 100], 'color': 'rgba(255, 0, 0, 0.05)'}
                ],
            }
        ))
        fig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font={'color': "white", 'family': "Arial"},
            height=220,
            margin=dict(l=20, r=20, t=40, b=20)
        )
        st.plotly_chart(fig, use_container_width=True)

    st.progress(min(int(payload["overall_score"]), 100))
    st.divider()

    # 3. Protocol Header Verification Display
    if show_headers and payload["header_results"]:
        st.subheader("🔑 Cryptographic Protocol Audit (SPF/DMARC)")
        hr = payload["header_results"]
        st.text(f"Declared Origin Address: {hr.get('from', 'Unknown Exception')}")
        st.text(f"Envelope Return-Path:   {hr.get('return_path', 'Unknown Exception')}")
        
        hc1, hc2 = st.columns(2)
        with hc1:
            st.code(f"SPF Policy Log:\n{hr.get('spf_policy', 'None Detected')}", language="text")
        with hc2:
            st.code(f"DMARC Policy Log:\n{hr.get('dmarc_policy', 'None Detected')}", language="text")
            
        for finding in hr.get("findings", []):
            st.caption(f"🛡️ {finding}")
        st.divider()

    # 4. Attachment Sandbox Metric Blocks
    if payload["attachment_results"]:
        st.subheader("📁 Ingested Binary Sandbox Analytics")
        ar = payload["attachment_results"]
        st.info(f"**Target Object Filename:** `{ar['filename']}`\n\n**SHA-256 Checksum Matrix:** `{ar['sha256']}`")
        st.write(f"**Threat Intelligence Registry Status:** {ar['status']}")
        st.divider()

    # 5. Content Profile Matrix (Clean & Deduplicated)
    st.subheader("🕵️ Contextual Heuristics & Sender Profile")
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("**Structural Anomalies**")
        if payload["indicators"]:
            for item in payload["indicators"]:
                st.write(f"⚠️ {item}")
        else:
            st.write("✅ Content matches standard behavioral indicators.")
    with c2:
        st.markdown("**Sender Reputation Context**")
        sr = payload["sender_result"]
        st.write(f"Heuristic Threat Weight: `{sr.get('score', 0)}`")
        for finding in sr.get("findings", []):
            st.write(f"• {finding}")
    st.divider()

    # 6. Deep Routing URL Mapping Logs (Cleaned domain profiles)
    if payload["url_results"]:
        st.subheader("🌐 Link Transport & Resolution Logging")
        for item in payload["url_results"]:
            with st.expander(f"Inspect Domain Profile: {item['domain']}"):
                st.markdown(f"**Sample Link Tracked:** `{item['shortened_url']}`")
                st.markdown(f"**Resolved Target:** `{item['final_destination']}`")
                st.markdown(f"**Domain Risk Factor:** `{item['score']}/100`")
                for internal_finding in item["findings"]:
                    st.caption(f"❌ {internal_finding}")
        st.divider()

    # 7. Threat Database Verification Metrics
    if mode == "Online" and payload["vt_result"]:
        st.subheader("🌐 Global Malware Engine Telemetry")
        vt = payload["vt_result"]
        v1, v2, v3, v4 = st.columns(4)
        v1.metric("Confirmed Malicious Hits", vt.get("malicious", 0))
        v2.metric("Suspicious Pattern Matches", vt.get("suspicious", 0))
        v3.metric("Clean Records", vt.get("harmless", 0))
        v4.metric("Undetected Classifications", vt.get("undetected", 0))
        st.divider()

    # 8. Forensic Actions & Automated Reporting
    st.subheader("🧠 Component Engine Attribution Weights")
    for system_source, component_weight in payload["explanation"].items():
        st.text(f"↳ Module Assignment [{system_source}]: +{component_weight}")
        
    st.subheader("📋 Incident Remediation Directives")
    st.warning(get_recommendation(payload["overall_score"]))

    st.subheader("📋 Auto-Generated Forensics Report")
    st.code(payload["report"], language="markdown")
    st.download_button(
        label="⬇️ Export Forensic Report (.md)",
        data=payload["report"],
        file_name="SentinelAI_Threat_Log.md",
        mime="text/markdown"
    )

# --- INTAKE INTERFACE: TAB 1 (EMAIL CORE) ---
with tab1:
    ingestion_format = st.radio(
        "Ingestion Interface Stream",
        ["Plain Text Email Body", "Raw Email Source (Headers Included)"],
        horizontal=True
    )
    email_raw_input = st.text_area("Paste Email Source Sequence Data", height=220)
    
    if st.button("Initialize Core Assessment Run"):
        if not email_raw_input.strip():
            st.warning("Action Deferred: Input Buffer Empty.")
        else:
            with st.spinner("Analyzing threat profile..."):
                analysis_payload = run_sentinel_pipeline(email_raw_input, ingestion_format, mode)
                render_dashboard(analysis_payload, show_headers=(ingestion_format == "Raw Email Source (Headers Included)"))

# --- INTAKE INTERFACE: TAB 2 (OCR GRABBER) ---
with tab2:
    st.subheader("📸 Content Extraction via OCR Processing")
    uploaded_image_file = st.file_uploader("Upload Target Graphic Matrix Asset", type=["png", "jpg", "jpeg"])
    
    if uploaded_image_file:
        extracted_ocr_string = extract_text(uploaded_image_file)
        st.text_area("OCR Frame Text Cache Output Preview", extracted_ocr_string, height=120)
        
        if st.button("Process Extracted Cache Matrix"):
            with st.spinner("Processing extracted OCR content..."):
                analysis_payload = run_sentinel_pipeline(extracted_ocr_string, "Plain Text Email Body", mode)
                render_dashboard(analysis_payload, show_headers=False)

# --- INTAKE INTERFACE: TAB 3 (FILE & PACKET SANDBOX) ---
with tab3:
    st.subheader("📁 Complete File Structure & MIME Parsing Sandbox")
    st.write("Upload an enterprise `.eml` structure asset file or a standalone attachment payload file to perform isolated integrity validation tracking.")
    
    upload_col1, upload_col2 = st.columns(2)
    with upload_col1:
        eml_upload = st.file_uploader("Ingest Electronic Mail Layout Asset (.eml)", type=["eml"])
    with upload_col2:
        binary_upload = st.file_uploader("Ingest Independent Binary/Document Payload", type=["exe", "pdf", "docx", "zip", "lnk", "bin"])

    if st.button("Execute Sandbox Extraction & Hash Audit"):
        processed_text = ""
        target_bytes = None
        target_name = None
        inferred_type = "Plain Text Email Body"

        if eml_upload:
            with st.spinner("Unpacking multi-part MIME metadata mapping layout..."):
                raw_bytes = eml_upload.read()
                parsed_message = message_from_bytes(raw_bytes)
                
                if parsed_message.is_multipart():
                    for part in parsed_message.walk():
                        disposition = str(part.get("Content-Disposition"))
                        if part.get_content_type() == "text/plain" and "attachment" not in disposition:
                            processed_text += part.get_payload(decode=True).decode(errors="ignore")
                        elif "attachment" in disposition:
                            target_bytes = part.get_payload(decode=True)
                            target_name = part.get_filename()
                else:
                    processed_text = parsed_message.get_payload(decode=True).decode(errors="ignore")
                
                if parsed_message.keys():
                    inferred_type = "Raw Email Source (Headers Included)"
                    processed_text = eml_upload.getvalue().decode(errors="ignore")
                
                st.success(f"Successfully decomposed layout configuration: Asset Subject -> \"{parsed_message.get('subject', 'Null Link Data')}\"")

        if binary_upload:
            target_bytes = binary_upload.getvalue()
            target_name = binary_upload.name
            if not processed_text:
                processed_text = f"Standalone payload verification run for filename: {target_name}"

        if not processed_text:
            st.error("Execution Denied: No data matrices loaded into buffer targets.")
        else:
            with st.spinner("Analyzing operational payload vectors..."):
                analysis_payload = run_sentinel_pipeline(
                    text=processed_text,
                    input_type=inferred_type,
                    mode=mode,
                    attachment_bytes=target_bytes,
                    attachment_name=target_name
                )
                render_dashboard(analysis_payload, show_headers=(inferred_type == "Raw Email Source (Headers Included)"))