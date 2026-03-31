import streamlit as st
import re
import hashlib
import json
import math
import urllib.request
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

# --- MATHEMATICAL SVG GENERATORS (NO EXTERNAL LIBRARIES) ---
def generate_svg_donut(percentage, color, title):
    """Uses Python's math library to calculate raw SVG arcs."""
    if percentage >= 99.99:
        path = f'<circle cx="50" cy="50" r="40" fill="none" stroke="{color}" stroke-width="12" />'
    elif percentage <= 0:
        path = ''
    else:
        angle = percentage * 3.6
        rad = math.radians(angle - 90)
        x = 50 + 40 * math.cos(rad)
        y = 50 + 40 * math.sin(rad)
        large_arc = 1 if angle > 180 else 0
        path = f'<path d="M 50 10 A 40 40 0 {large_arc} 1 {x} {y}" fill="none" stroke="{color}" stroke-width="12" stroke-linecap="round" />'
        
    return f'''
    <div style="text-align: center;">
        <svg viewBox="0 0 100 100" width="120px" height="120px">
            <circle cx="50" cy="50" r="40" fill="none" stroke="#30363d" stroke-width="12" />
            {path}
            <text x="50" y="50" font-family="Consolas" font-size="16" fill="{color}" text-anchor="middle" dominant-baseline="central" font-weight="bold">{percentage:.1f}%</text>
        </svg>
        <p style="font-family: Consolas; color: #8b949e; font-size: 14px; font-weight: bold;">{title}</p>
    </div>
    '''

def generate_severity_donut(critical, medium, low):
    """Calculates a multi-segment SVG donut chart for threat severities."""
    total = critical + medium + low
    if total == 0:
        return generate_svg_donut(0, "#8b949e", "SEVERITY SPLIT")
        
    angles = [(critical/total)*360, (medium/total)*360, (low/total)*360]
    colors = ["#f85149", "#d29922", "#2ea043"] # Red, Yellow, Green
    svg_paths = ""
    current_angle = 0
    
    for i in range(3):
        if angles[i] == 0: continue
        if angles[i] >= 359.9:
            svg_paths += f'<circle cx="50" cy="50" r="40" fill="none" stroke="{colors[i]}" stroke-width="12" />'
            continue
            
        start_rad = math.radians(current_angle - 90)
        x1 = 50 + 40 * math.cos(start_rad)
        y1 = 50 + 40 * math.sin(start_rad)
        
        end_rad = math.radians(current_angle + angles[i] - 90)
        x2 = 50 + 40 * math.cos(end_rad)
        y2 = 50 + 40 * math.sin(end_rad)
        
        large_arc = 1 if angles[i] > 180 else 0
        svg_paths += f'<path d="M {x1} {y1} A 40 40 0 {large_arc} 1 {x2} {y2}" fill="none" stroke="{colors[i]}" stroke-width="12" />'
        current_angle += angles[i]
        
    return f'''
    <div style="text-align: center;">
        <svg viewBox="0 0 100 100" width="120px" height="120px">
            <circle cx="50" cy="50" r="40" fill="none" stroke="#30363d" stroke-width="12" />
            {svg_paths}
            <text x="50" y="45" font-family="Consolas" font-size="20" fill="#c9d1d9" text-anchor="middle" font-weight="bold">{int(total)}</text>
            <text x="50" y="60" font-family="Consolas" font-size="8" fill="#8b949e" text-anchor="middle">TOTAL THREATS</text>
        </svg>
        <p style="font-family: Consolas; color: #8b949e; font-size: 14px; font-weight: bold;">SEVERITY SPLIT</p>
    </div>
    '''

# --- ZERO-DEPENDENCY GEMINI API CLIENT ---
def call_gemini_api(api_key, context_data):
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
    headers = {'Content-Type': 'application/json'}
    prompt = f"Act as an elite Cybersecurity Analyst. Review these flagged system incidents. Give a 3-sentence executive summary of the danger, followed by 3 bullet points of immediate actionable remediation steps:\n\n{context_data}"
    
    payload = {"contents": [{"parts": [{"text": prompt}]}]}
    req = urllib.request.Request(url, data=json.dumps(payload).encode('utf-8'), headers=headers)
    
    try:
        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode('utf-8'))
            return result['candidates'][0]['content']['parts'][0]['text']
    except urllib.error.URLError as e:
        return f"🚨 API Connection Failed. Please check your API Key. Error: {str(e)}"

# --- UI HEADER ---
st.title("🛡️ The Evidence Protector: Cloud Triage Dashboard")
st.markdown("Automated Log Integrity Monitor with Deterministic AI Confidence Scoring")

# --- SIDEBAR CONTROLS ---
with st.sidebar:
    st.header("⚙️ Configuration")
    selected_format = st.selectbox("Log Format Profile", list(LOG_FORMATS.keys()))
    threshold_sec = st.slider("Suspicion Threshold (Seconds)", min_value=10, max_value=300, value=60, step=10)
    uploaded_file = st.file_uploader("Upload Server Log", type=["log", "txt"])
    
    st.markdown("---")
    st.header("🧠 Generative AI Setup")
    gemini_key = st.text_input("Gemini API Key (Optional)", type="password", help="Enter your Gemini API key to unlock automated Executive Summaries.")

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

    # --- MATH-BASED METRICS DASHBOARD ---
    st.markdown("---")
    
    tot_float = float(total_lines)
    malf_float = float(malformed_lines)
    health_pct = 100.0 if tot_float == 0 else ((tot_float - malf_float) / tot_float) * 100.0
    
    threats_list = [g for g in gaps if g["Severity"] in ["CRITICAL", "MEDIUM"]]
    fps_list = [g for g in gaps if g["Severity"] == "LOW"]
    
    total_gaps_float = float(len(gaps))
    density_pct = 0.0 if tot_float == 0 else (total_gaps_float / tot_float) * 100.0
    
    crit_count = sum(1 for g in gaps if g["Severity"] == "CRITICAL")
    med_count = sum(1 for g in gaps if g["Severity"] == "MEDIUM")
    low_count = sum(1 for g in gaps if g["Severity"] == "LOW")

    # Top Row: Text KPIs
    col1, col2, col3 = st.columns(3)
    col1.metric("Cryptographic Anchor", f"{file_hash.hexdigest()[:12]}...")
    col2.metric("Total Lines Scanned", f"{total_lines:,}")
    col3.metric("Malformed Data Packets", f"{malformed_lines:,}")

    st.write("") # Spacer
    
    # Bottom Row: Mathematical SVG Donuts!
    d1, d2, d3 = st.columns(3)
    with d1: st.markdown(generate_svg_donut(health_pct, "#2ea043", "LOG HEALTH"), unsafe_allow_html=True)
    with d2: st.markdown(generate_svg_donut(density_pct, "#d29922", "ANOMALY DENSITY"), unsafe_allow_html=True)
    with d3: st.markdown(generate_severity_donut(crit_count, med_count, low_count), unsafe_allow_html=True)

    # --- EXPORT BUTTONS ---
    if gaps:
        st.sidebar.markdown("### 💾 Export Reports")
        clean_export_data = [{k: v for k, v in g.items() if not k.startswith('_')} for g in gaps]
        
        df_export = pd.DataFrame(clean_export_data)
        csv_data = df_export.to_csv(index=False).encode('utf-8')
        st.sidebar.download_button("📄 Download CSV", data=csv_data, file_name="forensic_report.csv", mime="text/csv")
        
        json_data = json.dumps(clean_export_data, indent=4).encode('utf-8')
        st.sidebar.download_button("🗄️ Download JSON", data=json_data, file_name="forensic_report.json", mime="application/json")

    # --- GEMINI AI EXECUTIVE REPORT GENERATOR ---
    st.markdown("---")
    st.subheader("🤖 Generative AI Executive Summary")
    if threats_list:
        if gemini_key:
            if st.button("✨ Generate Incident Report via Gemini"):
                with st.spinner("Connecting to Gemini via standard REST API..."):
                    # Prepare a condensed payload so we don't blow up the API token limit
                    condensed_context = "\n".join([f"ID: {t['ID']} | Duration: {t['Duration (s)']}s | Velocity Before: {t['EPM Before']} | Classification: {t['Reason']}" for t in threats_list[:15]])
                    
                    gemini_response = call_gemini_api(gemini_key, condensed_context)
                    st.info(gemini_response)
        else:
            st.warning("👈 Enter your Gemini API Key in the sidebar to automatically generate an executive summary of these threats.")
    else:
        st.success("No active threats to summarize.")

    # --- INTERACTIVE TABBED UI ---
    st.markdown("---")
    tab1, tab2 = st.tabs(["🚨 Active Threats & Forensics", "✅ False Positives & Noise"])
    
    with tab1:
        st.subheader("High & Medium Priority Incidents")
        st.caption("💡 **Click on any row** in the table below to instantly generate its Deep Dive AI Report.")
        
        if threats_list:
            display_threats = [{k: v for k, v in t.items() if not k.startswith('_') and k not in ['context_before', 'first_log_after', 'Reason']} for t in threats_list]
            df_threats = pd.DataFrame(display_threats)
            
            event = st.dataframe(df_threats, use_container_width=True, on_select="rerun", selection_mode="single-row", hide_index=True)
            
            if event.selection.rows:
                selected_idx = event.selection.rows[0]
                target_gap = next(t for t in threats_list if t["ID"] == df_threats.iloc[selected_idx]["ID"])
                
                st.subheader(f"🧠 Local Deterministic AI Insight: {target_gap['ID']}")
                if target_gap["Severity"] == "CRITICAL":
                    ai_insight = f"High likelihood of targeted log deletion or massive brute-force script. The engine detected a sudden silence immediately following a period of high server velocity (**{target_gap['EPM Before']} EPM**)."
                else:
                    ai_insight = "Suspicious temporal silence detected. The velocity leading up to this gap was normal, which may indicate stealth evasion or a non-standard system hang."
                
                st.info(f"**Insight:** {ai_insight}")
                st.markdown(f"**Classification:** `{target_gap['Reason']}` | **Confidence:** `{target_gap['Confidence']}`")
                
                st.markdown("#### 🕒 System State Immediately Before Anomaly")
                st.code("\n".join(target_gap["context_before"]), language="log")
                st.error(f"🚨 --- [ {target_gap['Duration (s)']} SECOND TEMPORAL GAP ] --- 🚨")
                st.markdown("#### 🟢 System Resumption")
                st.code(target_gap["first_log_after"], language="log")
                
        else:
            st.success("No active threats detected.")

    with tab2:
        st.subheader("Filtered Noise & Known Safe Gaps")
        st.caption("💡 **Click on any row** to see why the AI ignored this gap.")
        
        if fps_list:
            display_fps = [{k: v for k, v in f.items() if not k.startswith('_') and k not in ['context_before', 'first_log_after', 'EPM After', 'EPM Before', 'Severity']} for f in fps_list]
            df_fps = pd.DataFrame(display_fps)
            
            event_fp = st.dataframe(df_fps, use_container_width=True, on_select="rerun", selection_mode="single-row", hide_index=True)
            
            if event_fp.selection.rows:
                selected_idx = event_fp.selection.rows[0]
                target_fp = next(f for f in fps_list if f["ID"] == df_fps.iloc[selected_idx]["ID"])
                
                st.subheader(f"🧠 Local Deterministic AI Insight: {target_fp['ID']}")
                st.success("Routine system event. The semantic keyword scanner detected normal reboot or initialization terms immediately prior to the silence.")
                st.markdown(f"**Classification:** `{target_fp['Reason']}` | **Confidence:** `{target_fp['Confidence']}`")
                
                st.markdown("#### 🕒 System Shutdown Sequence")
                st.code("\n".join(target_fp["context_before"]), language="log")
                st.warning(f"⏸️ --- [ {target_fp['Duration (s)']} SECOND ROUTINE SYSTEM DELAY ] --- ⏸️")
                st.markdown("#### 🟢 System Startup")
                st.code(target_fp["first_log_after"], language="log")
        else:
            st.write("No false positives detected.")
else:
    st.info("👈 Upload a log file in the sidebar to begin analysis.")
