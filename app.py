import streamlit as st
import re
import json
import csv
import hashlib
from datetime import datetime
import io

# --- PAGE CONFIGURATION ---
st.set_page_config(page_title="The Evidence Protector", page_icon="🛡️", layout="wide")

# --- CONFIGURATION ---
config = {
    "log_regex": r"^(\d{6} \d{6})\s+(\d+)\s+(\w+)\s+(.*)$",
    "date_format": "%y%m%d %H%M%S",
    "reboot_keywords": ["boot", "sys_init", "startup", "restarting"],
    "threshold": 60
}

# --- THE ENGINE ---
def process_log(uploaded_file):
    file_hash = hashlib.sha256()
    previous_time = None
    block_start_time = None
    gaps_found = []
    logs_since_last_gap = 0
    reboot_check_counter = 0
    malformed_lines = 0

    # Streamlit files are read as bytes, so we decode them line-by-line
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
                severity = "CRITICAL"
                conf = min(85.0 + (velocity_epm * 0.02) + (delta * 0.01), 99.5)
            else:
                severity = "MEDIUM"
                conf = min(65.0 + (delta * 0.01), 84.9)
                
            conf_rounded = round(conf, 1)
            
            gaps_found.append({
                "Incident_ID": len(gaps_found) + 1,
                "Gap_Start": previous_time.strftime("%Y-%m-%d %H:%M:%S"),
                "Gap_End": current_time.strftime("%Y-%m-%d %H:%M:%S"),
                "Duration_Sec": delta,
                "Velocity_EPM": velocity_epm,
                "Severity": severity,
                "Confidence_%": conf_rounded,
                "context": "Suspicious Silence"
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

# --- UI BUILDER ---
st.title("🛡️ The Evidence Protector")
st.markdown("### Zero-Install Cloud Forensic Triage Dashboard")
st.markdown("Upload a system log file to instantly detect tampering, mathematically score the threat, and anchor the evidence cryptographically.")

uploaded_file = st.file_uploader("📂 Upload System Log File (.log, .txt)", type=["log", "txt"])

if uploaded_file is not None:
    with st.spinner("Analyzing log data and generating AI confidence scores..."):
        results = process_log(uploaded_file)
        
    st.success("Analysis Complete!")
    
    # KPIs
    st.markdown("---")
    st.markdown(f"**Digital Anchor (SHA-256):** `{results['metadata']['sha256_anchor']}`")
    
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Gaps Detected", len(results["evidence"]))
    col2.metric("Corrupt Lines Bypassed", results["metadata"]["malformed_lines"])
    col3.metric("Threshold Rule", f"{config['threshold']}s")
    
    # Data Table
    st.markdown("### 📊 Forensic Evidence Table")
    if len(results["evidence"]) > 0:
        st.dataframe(results["evidence"], use_container_width=True)
        
        # Export Buttons
        st.markdown("### 💾 Export Reports")
        
        # Prepare CSV
        csv_buffer = io.StringIO()
        writer = csv.DictWriter(csv_buffer, fieldnames=results["evidence"][0].keys())
        writer.writeheader()
        writer.writerows(results["evidence"])
        
        # Prepare JSON
        json_data = json.dumps(results, indent=4)
        
        col_csv, col_json = st.columns(2)
        with col_csv:
            st.download_button(label="Download CSV Report", data=csv_buffer.getvalue(), file_name="forensic_report.csv", mime="text/csv")
        with col_json:
            st.download_button(label="Download JSON Payload", data=json_data, file_name="forensic_payload.json", mime="application/json")
    else:
        st.info("No suspicious time gaps detected in this log file.")