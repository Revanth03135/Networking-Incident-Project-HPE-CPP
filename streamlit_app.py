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
    st.subheader("📄 Schema Conversion Output")
    
    hpe_logs_dir = Path("schema_conversion")
    
    # File mapping: HPE logs to their schema outputs
    hpe_schema_map = {
        "hpe_logs.txt": "schema_output.json",
        "hpe_logs_2.txt": "schema_output (1).json"
    }
    
    # Get available HPE log files
    available_files = [f for f in hpe_schema_map.keys() if (hpe_logs_dir / f).exists()]
    
    if available_files:
        selected_file = st.selectbox("Select HPE Log File:", available_files)
        schema_file = hpe_schema_map[selected_file]
        
        # Load corresponding schema output
        schema_path = hpe_logs_dir / schema_file
        if schema_path.exists():
            with open(schema_path, 'r') as f:
                file_schema = json.load(f)
            
            st.markdown(f"**📁 Input:** `schema_conversion/{selected_file}`")
            st.markdown(f"**📊 Output:** `schema_conversion/{schema_file}`")
            st.markdown("---")
            
            # Convert to table format
            if isinstance(file_schema, list) and len(file_schema) > 0:
                # Extract key fields for each event
                table_data = []
                for event in file_schema:
                    table_data.append({
                        "Event ID": event.get('event', {}).get('event_id', 'N/A'),
                        "Type": event.get('event', {}).get('type', 'N/A'),
                        "Subtype": event.get('event', {}).get('subtype', 'N/A'),
                        "Severity": event.get('event', {}).get('severity', 'N/A'),
                        "Device": event.get('device', {}).get('hostname', 'N/A'),
                        "IP": event.get('device', {}).get('ip_address', 'N/A'),
                        "Timestamp": event.get('timestamp', {}).get('original', 'N/A'),
                        "Message": event.get('event', {}).get('message', 'N/A')[:50]
                    })
                
                df = pd.DataFrame(table_data)
                st.markdown(f"**Total Events:** {len(df)}")
                st.dataframe(df, use_container_width=True, hide_index=True)
            else:
                st.json(file_schema)
        else:
            st.warning(f"⚠️ Output file not found: {schema_file}")
    else:
        st.info("No HPE log files found in schema_conversion directory")


# ============================================================
# TAB 3: TIMELINE RECONSTRUCTION
# ============================================================
with tab3:
    st.subheader("⏱️ Timeline Reconstruction Output")
    
    if timeline_output:
        st.markdown("**📁 Data Source:** `pipeline_output/timeline_output.json`")
        st.markdown("---")
        
        incidents = timeline_output if isinstance(timeline_output, list) else []
        
        if incidents:
            st.markdown(f"**Total Incidents:** {len(incidents)}")
            st.markdown("---")
            
            # Summary table
            summary_data = []
            for inc in incidents:
                summary_data.append({
                    "Incident ID": inc.get('incident_id', 'N/A'),
                    "Start Time": str(inc.get('start_time', 'N/A'))[:19],
                    "End Time": str(inc.get('end_time', 'N/A'))[:19],
                    "Duration (s)": inc.get('duration_sec', 0),
                    "Devices": ', '.join(inc.get('devices', [])),
                    "Events": len(inc.get('events', [])),
                    "Primary Issue": inc.get('summary', {}).get('primary_issue', 'N/A')[:40]
                })
            
            df_summary = pd.DataFrame(summary_data)
            st.markdown("### Incidents Summary")
            st.dataframe(df_summary, use_container_width=True, hide_index=True)
            
            # Detailed view per incident
            st.markdown("---")
            st.markdown("### Incident Details")
            
            incident_ids = [f"INC-{str(inc.get('incident_id', i)).zfill(4)}" for i, inc in enumerate(incidents)]
            selected_incident = st.selectbox("Select Incident:", incident_ids)
            
            incident_idx = incident_ids.index(selected_incident)
            incident = incidents[incident_idx]
            
            # Events table for selected incident
            events = incident.get('events', [])
            if events:
                events_data = []
                for evt in events:
                    events_data.append({
                        "Time": str(evt.get('corrected_time', 'N/A'))[:19],
                        "Device": evt.get('device', 'N/A'),
                        "Event Type": evt.get('type', 'N/A'),
                        "Subtype": evt.get('subtype', 'N/A'),
                        "Severity": evt.get('severity', 'N/A'),
                        "Relation": evt.get('relation_label', 'N/A'),
                        "Message": evt.get('message', 'N/A')[:40]
                    })
                
                df_events = pd.DataFrame(events_data)
                st.markdown(f"#### Events in {selected_incident}")
                st.dataframe(df_events, use_container_width=True, hide_index=True)
        else:
            st.info("No incidents found")
    else:
        st.info("Timeline output not loaded")


# ============================================================
# TAB 4: CAUSAL INFERENCE
# ============================================================
with tab4:
    st.subheader("🔗 Causal Inference Output")
    
    if causal_output:
        st.markdown("**📁 Data Source:** `pipeline_output/causal_inference_output.json`")
        st.markdown("---")
        
        # Summary metrics
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("🔗 Causal Links", causal_output.get('num_causal_links', 0))
        col2.metric("🚀 Incident Flows", causal_output.get('num_flows', 0))
        col3.metric("🔥 Root Causes", len(causal_output.get('root_causes', [])))
        col4.metric("🖥️ Devices", len(causal_output.get('affected_devices', [])))
        
        st.markdown("---")
        
        # Root Causes
        root_causes = causal_output.get('root_causes', [])
        if root_causes:
            st.markdown("### Root Cause Events")
            root_data = []
            for cause in root_causes:
                root_data.append({"Root Cause": cause})
            df_root = pd.DataFrame(root_data)
            st.dataframe(df_root, use_container_width=True, hide_index=True)
        
        st.markdown("---")
        
        # Causal Links Table
        links = causal_output.get('causal_links', [])
        if links:
            st.markdown(f"### Causal Links ({len(links)} total)")
            
            links_data = []
            for link in links:
                links_data.append({
                    "Cause Event": link.get('cause_subtype', 'N/A'),
                    "Cause Device": link.get('cause_device', 'N/A'),
                    "Effect Event": link.get('effect_subtype', 'N/A'),
                    "Effect Device": link.get('effect_device', 'N/A'),
                    "Time Lag (s)": link.get('lag_sec', 0),
                    "Confidence": f"{link.get('confidence', 0):.3f}",
                    "Type": link.get('link_type', 'N/A')
                })
            
            df_links = pd.DataFrame(links_data)
            st.dataframe(df_links, use_container_width=True, hide_index=True)
        
        st.markdown("---")
        
        # Affected Devices
        devices = causal_output.get('affected_devices', [])
        if devices:
            st.markdown("### Affected Devices")
            dev_data = []
            for dev in devices:
                dev_data.append({"Device": dev})
            df_devices = pd.DataFrame(dev_data)
            st.dataframe(df_devices, use_container_width=True, hide_index=True)
    else:
        st.info("Causal inference output not loaded")


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
