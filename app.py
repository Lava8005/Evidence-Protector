import streamlit as st
import re
import hashlib
import json
from datetime import datetime
from collections import deque
import pandas as pd

# --- CONFIGURATION & SETUP ---
st.set_page_config(page_title="Evidence Protector: Cloud SOC", page_icon="🛡️", layout="wide")

LOG_FORMATS = {
    "Ideathon Default (HDFS)": {"regex": r"^(\d{6} \d{6})\s+(\d+)\s+(\w+)\s+(.*)$", "date_fmt": "%y%m%d %H%M%S"},
    "Standard Syslog": {"regex": r"^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)$", "date_fmt": "%b %d %H:%M:%S"},
    "ISO 8601 (Cloud)": {"regex": r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\s+(.*)$", "date_fmt": "%Y-%m-%dT%H:%M:%S"}
}

REBOOT_KEYWORDS = ["boot", "sys_init", "startup", "restarting", "shutdown"]

# --- UI HEADER ---
st.title("🛡️ The Evidence Protector: Cloud Triage Dashboard")
st.markdown("Automated Log Integrity Monitor with Deterministic AI Confidence Scoring")

# --- SIDEBAR CONTROLS ---
with st.sidebar:
    st.header("⚙️ Configuration")
    selected_format = st.selectbox("Log Format Profile", list(LOG_FORMATS.keys()))
    threshold_sec = st.slider("Suspicion Threshold (Seconds)", min_value=10, max_value=300, value=60, step=10)
    uploaded_file = st.file_uploader("Upload Server Log", type=["log", "txt"])

# --- CORE INTELLIGENCE ENGINE ---
if uploaded_file is not None:
    regex_pattern = LOG_FORMATS[selected_format]["regex"]
    date_fmt = LOG_FORMATS[selected_format]["date_fmt"]
    
    file_hash = hashlib.sha256()
    first_time, previous_time, block_start_time = None, None, None
    logs_since_last_gap = 0
    total_lines, malformed_lines = 0, 0
    
    gaps = []
    recent_logs = deque(maxlen=3)
    
    with st.spinner("Executing O(1) Memory Scan & Calculating Threat Matrices..."):
        for line_bytes in uploaded_file:
            total_lines += 1
            line_clean = line_bytes.decode('utf-8', errors='replace').strip()
            file_hash.update(line_clean.encode('utf-8'))
            
            match = re.match(regex_pattern, line_clean)
            if not match:
                malformed_lines += 1
                continue
            
            groups = match.groups()
            timestamp_str = groups[0]
            message_content = groups[-1]
            
            if "Syslog" in selected_format:
                timestamp_str = f"{datetime.now().year} {timestamp_str}"
                date_fmt = "%Y %b %d %H:%M:%S"
                
            try:
                current_time = datetime.strptime(timestamp_str, date_fmt)
            except ValueError:
                malformed_lines += 1
                continue

            if first_time is None:
                first_time = current_time
                block_start_time = current_time

            if previous_time is None:
                previous_time = current_time
                recent_logs.append(message_content)
                continue

            # Calculate EPM After the gap for the PREVIOUS incident
            if gaps and gaps[-1]["_epm_after_raw"] is None:
                gaps[-1]["_post_gap_logs"] += 1
                time_since_gap = (current_time - gaps[-1]["_gap_end_time"]).total_seconds()
                
                if gaps[-1]["first_log_after"] == "N/A":
                    gaps[-1]["first_log_after"] = message_content
                    
                if time_since_gap >= 60 or total_lines % 500 == 0:
                    gaps[-1]["_epm_after_raw"] = round(gaps[-1]["_post_gap_logs"] / max(time_since_gap/60, 1), 2)

            delta = (current_time - previous_time).total_seconds()
            
            if delta > threshold_sec:
                block_duration = max((previous_time - block_start_time).total_seconds() / 60.0, 0.1)
                epm_before = round(logs_since_last_gap / block_duration, 2)
                
                context_string = " ".join(recent_logs).lower()
                is_reboot = any(kw in context_string for kw in REBOOT_KEYWORDS)
                
                if is_reboot:
                    severity, conf, reason = "LOW", 98.5, "Routine System Reboot"
                elif epm_before > 15:
                    severity, conf, reason = "CRITICAL", min(88.0 + (epm_before * 0.05), 99.9), "High Velocity Event"
                else:
                    severity, conf, reason = "MEDIUM", min(70.0 + (delta * 0.01), 87.9), "Suspicious Temporal Silence"
                        
                gaps.append({
                    "ID": f"INC-{len(gaps)+1:03d}",
                    "Gap Start": previous_time.strftime("%Y-%m-%d %H:%M:%S"),
                    "Duration (s)": int(delta),
                    "EPM Before": epm_before,
                    "EPM After": "Pending", 
                    "Severity": severity,
                    "Confidence": f"{round(conf, 1)}%",
                    "Reason": reason,
                    "context_before": list(recent_logs),
                    "_gap_end_time": current_time,
                    "_post_gap_logs": 0,
                    "_epm_after_raw": None,
                    "first_log_after": "N/A"
                })
                
                block_start_time = current_time
                logs_since_last_gap = 0
            
            previous_time = current_time
            logs_since_last_gap += 1
            recent_logs.append(message_content)

    for g in gaps:
        if g["_epm_after_raw"] is not None:
            g["EPM After"] = g["_epm_after_raw"]
        else:
            g["EPM After"] = "Insufficient Data"

    # --- EXECUTIVE METRICS DASHBOARD ---
    st.markdown("---")
    
    tot_float = float(total_lines)
    malf_float = float(malformed_lines)
    health_pct = 100.0 if tot_float == 0 else ((tot_float - malf_float) / tot_float) * 100.0
    health_str = "100%" if health_pct == 100.0 else ("0%" if health_pct == 0.0 else f"{min(health_pct, 99.9):.1f}%")
    
    threats_list = [g for g in gaps if g["Severity"] in ["CRITICAL", "MEDIUM"]]
    fps_list = [g for g in gaps if g["Severity"] == "LOW"]
    
    total_gaps_float = float(len(gaps))
    density_pct = 0.0 if tot_float == 0 else (total_gaps_float / tot_float) * 100.0
    density_str = "0%" if density_pct == 0.0 else f"{density_pct:.1f}%"

    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Cryptographic Anchor", f"{file_hash.hexdigest()[:8]}...")
    col2.metric("Total Lines Scanned", f"{total_lines:,}")
    col3.metric("Log Health", health_str)
    col4.metric("Active Threats", len(threats_list))
    col5.metric("Anomaly Density", density_str)

    # --- MULTI-FORMAT EXPORT STRETCH GOAL ---
    if gaps:
        st.sidebar.markdown("### 💾 Export Reports")
        
        # Strip out the internal variables (keys starting with '_') for clean external reports
        clean_export_data = [{k: v for k, v in g.items() if not k.startswith('_')} for g in gaps]
        
        # 1. CSV Export
        df_export = pd.DataFrame(clean_export_data)
        csv_data = df_export.to_csv(index=False).encode('utf-8')
        st.sidebar.download_button(
            label="📄 Download Report (CSV)",
            data=csv_data,
            file_name=f"forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )
        
        # 2. JSON Export
        json_data = json.dumps(clean_export_data, indent=4).encode('utf-8')
        st.sidebar.download_button(
            label="🗄️ Download Report (JSON)",
            data=json_data,
            file_name=f"forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json"
        )

    # --- INTEGRATED TABBED UI ---
    tab1, tab2 = st.tabs(["🚨 Active Threats & AI Analysis", "✅ False Positives & Noise"])
    
    with tab1:
        st.subheader("High & Medium Priority Incidents")
        if threats_list:
            display_threats = [{k: v for k, v in t.items() if not k.startswith('_') and k not in ['context_before', 'first_log_after', 'Reason']} for t in threats_list]
            st.dataframe(display_threats, use_container_width=True)
            
            st.markdown("---")
            
            st.subheader("🧠 Deep Dive AI Report")
            selected_threat_id = st.selectbox("Select an Incident ID from the table above for forensic breakdown:", [t["ID"] for t in threats_list])
            target_gap = next(t for t in threats_list if t["ID"] == selected_threat_id)
            
            if target_gap["Severity"] == "CRITICAL":
                ai_insight = f"High likelihood of targeted log deletion or massive brute-force script. The engine detected a sudden silence immediately following a period of high velocity ({target_gap['EPM Before']} EPM)."
            else:
                ai_insight = "Suspicious temporal silence detected. The velocity leading up to this gap was normal, which may indicate stealth evasion or a non-standard system hang."
            
            st.info(f"**🤖 AI ANALYSIS:** {ai_insight}")
            st.markdown(f"**Classification:** {target_gap['Reason']} | **Confidence:** {target_gap['Confidence']}")
            
            st.code("\n".join(target_gap["context_before"]), language="log")
            st.error(f"⚠️ --- [ {target_gap['Duration (s)']} SECOND TEMPORAL GAP ] --- ⚠️")
            st.code(target_gap["first_log_after"], language="log")
            
        else:
            st.success("No active threats detected in this log file.")

    with tab2:
        st.subheader("Filtered Noise & Known Safe Gaps")
        if fps_list:
            display_fps = [{k: v for k, v in f.items() if not k.startswith('_') and k not in ['context_before', 'first_log_after', 'EPM After', 'EPM Before', 'Severity']} for f in fps_list]
            st.dataframe(display_fps, use_container_width=True)
            
            st.markdown("---")
            
            st.subheader("🧠 Deep Dive AI Report")
            selected_fp_id = st.selectbox("Select an Incident ID to view the ignored sequence:", [f["ID"] for f in fps_list])
            target_fp = next(f for f in fps_list if f["ID"] == selected_fp_id)
            
            st.success(f"**🤖 AI ANALYSIS:** Routine system event. The semantic keyword scanner detected normal reboot or initialization terms immediately prior to the silence.")
            st.markdown(f"**Classification:** {target_fp['Reason']} | **Confidence:** {target_fp['Confidence']}")
            
            st.code("\n".join(target_fp["context_before"]), language="log")
            st.warning(f"⏸️ --- [ {target_fp['Duration (s)']} SECOND ROUTINE SYSTEM DELAY ] --- ⏸️")
            st.code(target_fp["first_log_after"], language="log")
        else:
            st.write("No false positives detected.")
else:
    st.info("👈 Upload a log file in the sidebar to begin analysis.")
