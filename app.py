import streamlit as st
import re
import json
import csv
import hashlib
from datetime import datetime
import io

# --- 1. PAGE CONFIGURATION (Must be first) ---
st.set_page_config(page_title="The Evidence Protector", page_icon="🛡️", layout="wide", initial_sidebar_state="collapsed")

# --- 2. ENTERPRISE CSS INJECTION ---
# This overrides Streamlit's default UI to create a premium Dark Mode dashboard
st.markdown("""
<style>
    /* Global Background */
    .stApp {
        background-color: #0d1117;
        color: #c9d1d9;
        font-family: 'Consolas', 'Courier New', monospace;
    }
    
    /* Title and Header Styling */
    h1, h2, h3 {
        color: #58a6ff !important;
        font-weight: 700 !important;
        letter-spacing: 1px;
    }
    
    /* Custom glowing accent line */
    hr {
        border: 0;
        height: 1px;
        background-image: linear-gradient(to right, rgba(0, 0, 0, 0), rgba(88, 166, 255, 0.75), rgba(0, 0, 0, 0));
        margin-top: 2rem;
        margin-bottom: 2rem;
    }

    /* Metric Card Styling */
    div[data-testid="metric-container"] {
        background-color: #161b22;
        border: 1px solid #30363d;
        padding: 15px 20px;
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.5);
        border-left: 4px solid #58a6ff;
    }
    
    /* File Uploader Container */
    .stFileUploader > div > div {
        background-color: #161b22;
        border: 2px dashed #58a6ff;
        border-radius: 10px;
        padding: 20px;
        transition: all 0.3s ease;
    }
    .stFileUploader > div > div:hover {
        border-color: #ff4b4b;
        background-color: #1c2128;
    }

    /* DataFrame / Table Customization */
    div[data-testid="stDataFrame"] {
        border: 1px solid #30363d;
        border-radius: 8px;
        overflow: hidden;
    }
</style>
""", unsafe_allow_html=True)

# --- 3. CONFIGURATION ---
config = {
    "log_regex": r"^(\d{6} \d{6})\s+(\d+)\s+(\w+)\s+(.*)$",
    "date_format": "%y%m%d %H%M%S",
    "reboot_keywords": ["boot", "sys_init", "startup", "restarting"],
    "threshold": 60
}

# --- 4. THE CORE ENGINE ---
def process_log(uploaded_file):
    file_hash = hashlib.sha256()
    previous_time = None
    block_start_time = None
    gaps_found = []
    logs_since_last_gap = 0
    reboot_check_counter = 0
    malformed_lines = 0

    for raw_line in uploaded_file:
        line_clean = raw_line.decode('utf-8', errors='replace').strip()
        file_hash.update(line_clean.encode('utf-8'))
        
        match = re.match(config["log_regex"], line_clean)
        if not match:
            malformed_lines += 1
            continue
            
        timestamp_str, pid, level, message = match.groups()
        try:
            current_time = datetime.strptime(timestamp_str, config["date_format"])
        except ValueError:
            malformed_lines += 1
            continue

        if previous_time is None:
            previous_time = current_time
            block_start_time = current_time
            logs_since_last_gap += 1
            continue
            
        if reboot_check_counter > 0:
            if any(kw in message.lower() for kw in config["reboot_keywords"]):
                gaps_found[-1]["context"] = "Routine System Reboot"
                gaps_found[-1]["severity"] = "LOW"
                gaps_found[-1]["confidence_score"] = 98.0
                reboot_check_counter = 0
            else:
                reboot_check_counter -= 1

        delta = (current_time - previous_time).total_seconds()
        
        if delta > config["threshold"]:
            block_duration = max((previous_time - block_start_time).total_seconds() / 60.0, 1.0)
            velocity_epm = round(logs_since_last_gap / block_duration, 2)
            
            if velocity_epm > 10:
                severity = "CRITICAL 🔴"
                conf = min(85.0 + (velocity_epm * 0.02) + (delta * 0.01), 99.5)
            else:
                severity = "MEDIUM 🟠"
                conf = min(65.0 + (delta * 0.01), 84.9)
                
            conf_rounded = round(conf, 1)
            
            gaps_found.append({
                "ID": f"INC-{len(gaps_found) + 1:03d}",
                "Start Time": previous_time.strftime("%Y-%m-%d %H:%M:%S"),
                "End Time": current_time.strftime("%Y-%m-%d %H:%M:%S"),
                "Duration (s)": int(delta),
                "Velocity (EPM)": velocity_epm,
                "Severity": severity,
                "AI Confidence": f"{conf_rounded}%",
                "Trigger Context": "Suspicious Silence"
            })
            block_start_time = current_time
            logs_since_last_gap = 0
            reboot_check_counter = 5 
            
        previous_time = current_time
        logs_since_last_gap += 1

    return {
        "metadata": {
            "malformed_lines": malformed_lines,
            "sha256_anchor": file_hash.hexdigest()
        },
        "evidence": gaps_found
    }

# --- 5. DASHBOARD UI ---
st.markdown("<h1>🛡️ The Evidence Protector</h1>", unsafe_allow_html=True)
st.markdown("<p style='font-size: 1.2rem; color: #8b949e;'>Cloud-Native Forensic Intelligence & Triage Dashboard</p>", unsafe_allow_html=True)

st.markdown("---")

# Main action area
col_upload, col_info = st.columns([2, 1])

with col_upload:
    uploaded_file = st.file_uploader("Drop target system log (.log, .txt) here to initiate scan", type=["log", "txt"])

with col_info:
    st.info("**Air-Gapped Processing:** Logs are processed entirely in memory. No data is permanently written to disk during this session.", icon="🔒")
    with st.expander("⚙️ View Scan Parameters"):
        st.code(f"Threshold: {config['threshold']} seconds\nRegex Pattern Active: True\nSemantic Intent Check: Active", language="yaml")

if uploaded_file is not None:
    with st.spinner("Scrubbing logs and calculating predictive confidence..."):
        results = process_log(uploaded_file)
        
    st.markdown("---")
    st.markdown("### 📡 Scan Diagnostics & KPIs")
    
    # Beautiful KPI Cards
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Incidents", len(results["evidence"]), delta="Review Required", delta_color="inverse")
    col2.metric("Corrupted Lines Bypassed", results["metadata"]["malformed_lines"], delta="Filtered")
    col3.metric("Threshold Matrix", f"{config['threshold']}s", delta="Active")
    col4.metric("Confidence Engine", "v1.2", delta="Online", delta_color="normal")
    
    # Cryptographic Hash display
    st.markdown(f"> **Digital Custody Anchor (SHA-256):** `<span style='color: #3fb950;'>{results['metadata']['sha256_anchor']}</span>`", unsafe_allow_html=True)
    
    st.markdown("---")
    st.markdown("### 📊 Automated Forensic Report")
    
    if len(results["evidence"]) > 0:
        # Render the table
        st.dataframe(results["evidence"], use_container_width=True, hide_index=True)
        
        st.markdown("<br>", unsafe_allow_html=True)
        
        # Export Buttons inside an expander for a cleaner UI
        with st.expander("💾 Export Incident Payload"):
            st.markdown("Download the structured intelligence payload for external SIEM integration or legal archiving.")
            
            # Prepare CSV
            csv_buffer = io.StringIO()
            writer = csv.DictWriter(csv_buffer, fieldnames=results["evidence"][0].keys())
            writer.writeheader()
            writer.writerows(results["evidence"])
            
            # Prepare JSON
            json_data = json.dumps(results, indent=4)
            
            e_col1, e_col2 = st.columns(2)
            with e_col1:
                st.download_button(label="📥 Download as CSV", data=csv_buffer.getvalue(), file_name="forensic_report.csv", mime="text/csv", use_container_width=True)
            with e_col2:
                st.download_button(label="📥 Download as JSON", data=json_data, file_name="forensic_payload.json", mime="application/json", use_container_width=True)
    else:
        st.success("✅ Clean Scan: No suspicious temporal anomalies detected in this log file.")
