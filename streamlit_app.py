"""
Streamlit Dashboard for Network Incident Analysis
==================================================
Displays schema conversion, timeline reconstruction, causal inference results
"""

import streamlit as st
import json
import pandas as pd
from pathlib import Path
from datetime import datetime
import plotly.graph_objects as go
import plotly.express as px
import subprocess
import tempfile

st.set_page_config(page_title="Network Incident Analysis", layout="wide", initial_sidebar_state="expanded")

# ============================================================
# SIDEBAR - FILE UPLOAD & CONFIGURATION
# ============================================================
st.sidebar.title("🔧 Configuration")

output_dir = st.sidebar.text_input(
    "Output Directory",
    value="pipeline_output",
    help="Path to pipeline output folder"
)

# Verify directory exists
output_path = Path(output_dir)
if not output_path.exists():
    st.sidebar.error(f"❌ Directory not found: {output_dir}")
    st.stop()

# Load output files
@st.cache_data
def load_json_file(filename):
    filepath = output_path / filename
    if filepath.exists():
        with open(filepath, 'r') as f:
            return json.load(f)
    return None

# Load all outputs
normalized_events = load_json_file("normalized_events.json")
schema_output = load_json_file("schema_output.json")
timeline_output = load_json_file("timeline_output.json")
causal_output = load_json_file("causal_inference_output.json")
incident_report_path = output_path / "incident_report.md"

st.sidebar.success("✅ All files loaded successfully!")

# ============================================================
# MAIN DASHBOARD
# ============================================================
st.title("🌐 Network Incident Analysis Dashboard")
st.markdown("---")

# Tabs for different views
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "📊 Overview",
    "🔄 Schema Conversion",
    "⏱️ Timeline Reconstruction",
    "🔗 Causal Inference",
    "📋 Incident Report"
])

# ============================================================
# TAB 1: OVERVIEW
# ============================================================
with tab1:
    st.subheader("📈 Analysis Summary")
    
    col1, col2, col3, col4 = st.columns(4)
    
    if timeline_output:
        incidents = timeline_output if isinstance(timeline_output, list) else []
        col1.metric("📍 Total Incidents", len(incidents))
    
    if normalized_events:
        col2.metric("🔔 Total Events", len(normalized_events))
    
    if causal_output:
        col3.metric("🔗 Causal Links", causal_output.get("num_causal_links", 0))
        col4.metric("🚀 Incident Flows", causal_output.get("num_flows", 0))
    
    st.markdown("---")
    
    # Devices affected
    if causal_output:
        devices = causal_output.get("affected_devices", [])
        st.markdown(f"**🖥️ Affected Devices:** {', '.join(devices)}")
    
    # Root causes
    if causal_output and causal_output.get("root_causes"):
        st.markdown(f"**🔥 Root Cause Events (Sample):** {', '.join(causal_output['root_causes'][:10])}")


# ============================================================
# TAB 2: SCHEMA CONVERSION
# ============================================================
with tab2:
    st.subheader("📄 Standardized Event Schema")
    st.markdown("""
    Raw logs converted to unified schema with:
    - Event classification (type, subtype, severity)
    - Device information (hostname, IP, vendor, OS)
    - Network details (interface, VLAN)
    - Timestamp normalization & clock skew correction
    """)
    
    # ============================================================
    # INPUT SECTION FOR LOG CONVERSION
    # ============================================================
    st.markdown("#### 📥 Convert Raw Logs to Schema")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        log_input = st.text_area(
            "Paste raw logs here:",
            height=150,
            placeholder="Paste network logs here (syslog, JSON, or raw text format)",
            help="Enter raw network logs in any format (syslog, JSON, plain text)"
        )
    
    with col2:
        st.markdown("")
        st.markdown("")
        uploaded_log_file = st.file_uploader(
            "Or upload a log file",
            type=["txt", "log", "json"],
            help="Upload .txt, .log, or .json files"
        )
    
    # Process button
    if st.button("🚀 Convert to Schema", key="schema_convert_btn"):
        if log_input or uploaded_log_file:
            with st.spinner("⏳ Converting logs to schema..."):
                try:
                    import subprocess
                    import tempfile
                    
                    # Determine input
                    if uploaded_log_file:
                        with tempfile.NamedTemporaryFile(delete=False, suffix=Path(uploaded_log_file.name).suffix) as tmp:
                            tmp.write(uploaded_log_file.getbuffer())
                            tmp_path = tmp.name
                        log_source = uploaded_log_file.name
                    else:
                        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as tmp:
                            tmp.write(log_input)
                            tmp_path = tmp.name
                        log_source = "Pasted logs"
                    
                    # Run pipeline
                    temp_output = Path(output_dir) / f"converted_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                    
                    cmd = [
                        "python",
                        "integrated_pipeline.py",
                        "--input", tmp_path,
                        "--output-dir", str(temp_output),
                        "--no-llm"
                    ]
                    
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                    
                    if result.returncode == 0:
                        st.success(f"✅ Successfully converted {log_source}!")
                        
                        # Load and display converted schema
                        converted_schema_path = temp_output / "schema_output.json"
                        if converted_schema_path.exists():
                            with open(converted_schema_path, 'r') as f:
                                converted_schema = json.load(f)
                            
                            st.markdown("---")
                            st.markdown("#### ✅ Converted Schema")
                            
                            # Display statistics
                            col1, col2, col3 = st.columns(3)
                            col1.metric("📊 Events Converted", len(converted_schema))
                            
                            event_types_conv = {}
                            for event in converted_schema:
                                etype = event.get('event', {}).get('type', 'Unknown')
                                event_types_conv[etype] = event_types_conv.get(etype, 0) + 1
                            col2.metric("📦 Event Types", len(event_types_conv))
                            col3.metric("🖥️ Devices", len(set(e.get('device', {}).get('hostname') for e in converted_schema if e.get('device'))))
                            
                            # Show converted events
                            st.markdown("##### Converted Events Sample")
                            for i, event in enumerate(converted_schema[:5]):
                                with st.expander(f"Event {i+1}: {event.get('event', {}).get('event_id', 'N/A')}"):
                                    st.json(event)
                    else:
                        st.error(f"❌ Conversion failed:\n{result.stderr[:500]}")
                    
                    # Cleanup
                    Path(tmp_path).unlink(missing_ok=True)
                    
                except Exception as e:
                    st.error(f"❌ Error: {str(e)}")
        else:
            st.warning("⚠️ Please paste logs or upload a file first!")
    
    st.markdown("---")
    
    if schema_output:
        # Show first few events
        st.markdown("#### Sample Events (First 5)")
        for i, event in enumerate(schema_output[:5]):
            with st.expander(f"Event {i+1}: {event.get('event', {}).get('event_id', 'N/A')}"):
                st.json(event)
        
        # Statistics
        col1, col2, col3 = st.columns(3)
        
        event_types = {}
        for event in schema_output:
            etype = event.get('event', {}).get('type', 'Unknown')
            event_types[etype] = event_types.get(etype, 0) + 1
        
        col1.metric("📦 Unique Event Types", len(event_types))
        col2.metric("🖥️ Devices", len(set(e.get('device', {}).get('hostname') for e in schema_output)))
        col3.metric("⚠️ Events", len(schema_output))
        
        # Event type distribution
        st.markdown("#### Event Type Distribution")
        df_types = pd.DataFrame(list(event_types.items()), columns=['Type', 'Count'])
        fig = px.bar(df_types, x='Type', y='Count', title="Events by Type")
        st.plotly_chart(fig, use_container_width=True)
        
        # Severity distribution
        st.markdown("#### Severity Distribution")
        severities = {}
        for event in schema_output:
            sev = event.get('event', {}).get('severity', 'Unknown')
            severities[sev] = severities.get(sev, 0) + 1
        
        df_sev = pd.DataFrame(list(severities.items()), columns=['Severity', 'Count'])
        colors = {'critical': '#FF6B6B', 'error': '#FFA500', 'warning': '#FFD93D', 'info': '#6BCB77'}
        fig = px.pie(df_sev, values='Count', names='Severity', title="Events by Severity", color='Severity', color_discrete_map=colors)
        st.plotly_chart(fig, use_container_width=True)


# ============================================================
# TAB 3: TIMELINE RECONSTRUCTION
# ============================================================
with tab3:
    st.subheader("⏱️ Incident Timeline")
    st.markdown("Events grouped into incidents with temporal correlation and deduplication")
    
    if timeline_output:
        incidents = timeline_output if isinstance(timeline_output, list) else []
        
        # Incident selector
        incident_names = [f"INC-{inc.get('incident_id', i).zfill(4)}" for i, inc in enumerate(incidents)]
        selected_incident = st.selectbox("Select Incident", incident_names)
        
        incident_idx = incident_names.index(selected_incident)
        incident = incidents[incident_idx]
        
        # Incident metrics
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("⏱️ Duration (sec)", incident.get("duration_sec", 0))
        col2.metric("🔔 Events", len(incident.get("events", [])))
        col3.metric("🖥️ Devices", len(incident.get("devices", [])))
        col4.metric("📊 Confidence", f"{incident.get('incident_confidence', 0):.2f}")
        
        st.markdown("---")
        
        # Primary issue
        primary = incident.get("summary", {}).get("primary_issue", "N/A")
        st.markdown(f"**🎯 Primary Issue:** {primary}")
        
        # Root cause
        root_cause_conf = incident.get("root_cause_confidence", 0)
        st.markdown(f"**🔥 Root Cause Event Confidence:** {root_cause_conf:.2f}")
        
        # Events timeline
        st.markdown("#### Event Timeline")
        events = incident.get("events", [])
        timeline_data = []
        
        for evt in events:
            timeline_data.append({
                "Time": evt.get("corrected_time", "N/A"),
                "Device": evt.get("device", "N/A"),
                "Event": evt.get("subtype", "N/A"),
                "Severity": evt.get("severity", "N/A"),
                "Relation": evt.get("relation_label", "N/A")
            })
        
        df_timeline = pd.DataFrame(timeline_data)
        st.dataframe(df_timeline, use_container_width=True, hide_index=True)
        
        # Related vs Unrelated
        col1, col2 = st.columns(2)
        related = incident.get("summary", {}).get("related_event_ids", [])
        unrelated = incident.get("summary", {}).get("unrelated_event_ids", [])
        col1.metric("✅ Related Events", len(related))
        col2.metric("❌ Unrelated Events", len(unrelated))


# ============================================================
# TAB 4: CAUSAL INFERENCE
# ============================================================
with tab4:
    st.subheader("🔗 Causal Relationships")
    st.markdown("Inferred cause-effect relationships with confidence scores and time lags")
    
    if causal_output:
        col1, col2, col3 = st.columns(3)
        col1.metric("🔗 Total Links", causal_output.get("num_causal_links", 0))
        col2.metric("🚀 Flows", causal_output.get("num_flows", 0))
        col3.metric("🔥 Root Causes", len(causal_output.get("root_causes", [])))
        
        st.markdown("---")
        
        # Causal links table
        st.markdown("#### Sample Causal Links (First 20)")
        links = causal_output.get("causal_links", [])
        
        links_data = []
        for link in links[:20]:
            links_data.append({
                "Cause": f"{link.get('cause_subtype')} @ {link.get('cause_device')}",
                "Effect": f"{link.get('effect_subtype')} @ {link.get('effect_device')}",
                "Lag (sec)": link.get("lag_sec", 0),
                "Confidence": f"{link.get('confidence', 0):.2f}"
            })
        
        df_links = pd.DataFrame(links_data)
        st.dataframe(df_links, use_container_width=True, hide_index=True)
        
        # Confidence distribution
        st.markdown("#### Confidence Score Distribution")
        confidences = [link.get("confidence", 0) for link in links]
        fig = px.histogram(x=confidences, nbins=20, title="Causal Link Confidence Scores", labels={"x": "Confidence", "y": "Count"})
        st.plotly_chart(fig, use_container_width=True)
        
        # Lag distribution
        st.markdown("#### Time Lag Distribution")
        lags = [link.get("lag_sec", 0) for link in links]
        fig = px.histogram(x=lags, nbins=20, title="Causal Link Time Lags", labels={"x": "Lag (seconds)", "y": "Count"})
        st.plotly_chart(fig, use_container_width=True)


# ============================================================
# TAB 5: INCIDENT REPORT
# ============================================================
with tab5:
    st.subheader("📋 Full Incident Report")
    
    if incident_report_path.exists():
        with open(incident_report_path, 'r') as f:
            report_content = f.read()
        
        st.markdown(report_content)
    else:
        st.warning("Incident report not found!")


# ============================================================
# FOOTER
# ============================================================
st.markdown("---")
st.markdown("""
<div style="text-align: center;">
    <small>Network Incident Analysis Dashboard | HPE CPP Project</small>
</div>
""", unsafe_allow_html=True)
