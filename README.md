# Networking Incident Project — HPE CPP

An end-to-end pipeline that ingests raw network syslog files and produces structured incident reports with automated root-cause analysis. The system uses a combination of deterministic heuristics, graph algorithms (Louvain community detection, DAG-based causal inference), and optional LLM augmentation to reconstruct incidents from raw log lines.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Pipeline Stages](#pipeline-stages)
   - [Stage 1 — Log Ingestion & Schema Conversion](#stage-1--log-ingestion--schema-conversion)
   - [Stage 2 — Preprocessing](#stage-2--preprocessing)
   - [Stage 3 — Implicit Topology Extraction](#stage-3--implicit-topology-extraction)
   - [Stage 4 — Timeline Reconstruction](#stage-4--timeline-reconstruction)
   - [Stage 5 — Causal Inference & Root-Cause Analysis](#stage-5--causal-inference--root-cause-analysis)
   - [Stage 6 — Validation & Incident Splitting](#stage-6--validation--incident-splitting)
   - [Stage 7 — Report Generation](#stage-7--report-generation)
3. [Data Flow](#data-flow)
4. [Key Design Decisions](#key-design-decisions)
5. [Event Classification Reference](#event-classification-reference)
6. [Getting Started](#getting-started)
7. [Output Artifacts](#output-artifacts)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                      Raw Syslog / Log File                         │
│              (.txt, .log, or pre-structured .json)                 │
└──────────────────────────┬──────────────────────────────────────────┘
                           ▼
┌──────────────────────────────────────────────────────────────────────┐
│  STAGE 1: Log Ingestion & Schema Conversion                         │
│  (log_processor.py / integrated_pipeline.py fallback)               │
│  Regex template matching → LLM fallback → Normalized event schema   │
└──────────────────────────┬──────────────────────────────────────────┘
                           ▼
┌──────────────────────────────────────────────────────────────────────┐
│  STAGE 2: Preprocessing                                             │
│  (preprocessing.py)                                                 │
│  Flatten → Parse timestamps → Clock-skew correction → Dynamic window│
└──────────────────────────┬──────────────────────────────────────────┘
                           ▼
┌──────────────────────────────────────────────────────────────────────┐
│  STAGE 3: Implicit Topology Extraction                              │
│  (topology_extraction.py)                                           │
│  Tier 1: Explicit IP cross-refs  |  Tier 2: Shared VLAN/subnet     │
│  Tier 3: BGP/OSPF peer matches   →  Undirected weighted graph      │
└──────────────────────────┬──────────────────────────────────────────┘
                           ▼
┌──────────────────────────────────────────────────────────────────────┐
│  STAGE 4: Timeline Reconstruction                                   │
│  (timeline_reconstruction.py)                                       │
│  Pairwise compatibility scoring → Louvain community detection       │
│  → Incident partitioning → Deduplication                            │
└──────────────────────────┬──────────────────────────────────────────┘
                           ▼
┌──────────────────────────────────────────────────────────────────────┐
│  STAGE 5: Causal Inference & Root-Cause Analysis                    │
│  (causalInference/causalInference.py)                               │
│  Directed Acyclic Graph (DAG) → Causal sequence extraction          │
│  → Root-cause scoring → Recovery event filtering                    │
└──────────────────────────┬──────────────────────────────────────────┘
                           ▼
┌──────────────────────────────────────────────────────────────────────┐
│  STAGE 6: Validation & Incident Splitting                           │
│  (causalInference/causalInference.py → validate_and_split)          │
│  Disconnected components → Split into sub-incidents                 │
│  → Re-attach recovery events to matching components                 │
└──────────────────────────┬──────────────────────────────────────────┘
                           ▼
┌──────────────────────────────────────────────────────────────────────┐
│  STAGE 7: Report Generation                                         │
│  Markdown report (LLM or fallback) + HTML visualization + PDF       │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Pipeline Stages

### Stage 1 — Log Ingestion & Schema Conversion

**Files:** [`schema_conversion/log_processor.py`](schema_conversion/log_processor.py), [`integrated_pipeline.py`](integrated_pipeline.py)

**Purpose:** Transform raw syslog lines into a structured, normalized event schema.

**How it works:**

1. **Raw log parsing** — Each syslog line is parsed to extract:
   - Timestamp (BSD syslog `May 14 14:00:49` or ISO-8601)
   - Hostname / IP address
   - Facility and severity from bracket notation (`[daemon.warning]`)
   - Core message (stripping the syslog header)

2. **Fast regex template matching** — Before any LLM call, the core message is tested against a library of pre-compiled regex patterns stored in [`schema_conversion/template_registry.json`](schema_conversion/template_registry.json). Each template carries a pre-defined schema (type, subtype, severity) so matching logs are instantly classified. This is the primary classification path and handles the majority of log lines without network calls.

3. **LLM fallback** — If no regex matches and `--no-llm` is not set, the log is sent through a 3-stage LLM pipeline:
   - **Stage 1 (Extraction):** Extract core message and metadata
   - **Stage 2 (Semantic Analysis):** Classify type, subtype, severity
   - **Stage 3 (Formatting):** Produce the final normalized schema
   - A new template is generated and saved to the registry for future matches.

4. **Inline fallback extractor** — If the LLM endpoint is unavailable and the log processor produces zero records, `integrated_pipeline.py` activates a keyword-based fallback that detects subtypes using a priority-ordered rule list (`_SUBTYPE_RULES`).

**Output schema per event:**

```json
{
  "event":      { "event_uid", "type", "subtype", "severity", "message" },
  "device":     { "hostname", "ip", "vendor", "os" },
  "network":    { "interface_id", "vlan" },
  "timestamps": { "event_time", "ingestion_time" },
  "raw":        { "message" }
}
```

---

### Stage 2 — Preprocessing

**File:** [`preprocessing.py`](preprocessing.py)

**Purpose:** Flatten the nested event schema, parse timestamps, correct clock skew, and compute a dynamic clustering time-window.

**Steps:**

| Step | Function | Description |
|------|----------|-------------|
| 1 | `flatten_events()` | Collapse nested `event/device/network/timestamps/raw` dicts into a flat dict with top-level keys like `device`, `severity`, `message`, `event_time`, etc. |
| 2 | `normalize_timestamps()` | Parse ISO-8601 strings into `datetime` objects. Events with unparseable timestamps are dropped. |
| 3 | `correct_clock_skew()` | Compute per-device median skew between `ingestion_time` and `event_time`, then create a `corrected_time` field adjusted by that median. |
| 4 | `compute_dynamic_window()` | IQR-based window: `max(2.0, median_gap + 1.5 × IQR)`. This adaptive window is used downstream for clustering decisions. |

**Output:** `preprocessed_events.json` — flat event list with `corrected_time` attached.

---

### Stage 3 — Implicit Topology Extraction

**File:** [`topology_extraction.py`](topology_extraction.py)

**Purpose:** Infer device-to-device connectivity from log content alone, without requiring an explicit physical topology file.

**Three-tier evidence model:**

| Tier | Signal | Weight | Example |
|------|--------|--------|---------|
| **Tier 1** | Explicit IP cross-references — Device A's log mentions Device B's management IP | **1.0** | Router-1's BGP log references switch-1's IP `192.168.1.10` |
| **Tier 2** | Shared VLAN co-membership | **0.6** | Both devices reference VLAN 20 |
| **Tier 2b** | Shared /24 subnet | **0.4** | Both devices have IPs in `10.0.0.0/24` |
| **Tier 2c** | Shared MAC address reference | **0.5** | Both devices log the same client MAC |
| **Tier 3** | BGP/OSPF peer IP matches (captured via Tier 1) | (via Tier 1) | OSPF neighbor IP resolves to a known device |

**Output:** An undirected weighted `nx.Graph` saved to `topology_graph.json`. Also provides pairwise helper functions used by Stage 4: `shares_explicit_reference()`, `shares_vlan_or_subnet()`, `shares_interface_reference()`, `same_client_mac()`.

---

### Stage 4 — Timeline Reconstruction

**File:** [`timeline_reconstruction.py`](timeline_reconstruction.py)

**Purpose:** Group preprocessed events into discrete incidents using graph-based community detection instead of naive time-window clustering.

**Key architectural decision:** Shared topology and identifiers are the **primary** grouping signal; time proximity is **secondary**. This prevents temporally proximate but causally unrelated events from being incorrectly merged.

**Sub-stages:**

#### Stage 4a — Temporal Alignment
Sort all events by `corrected_time`. Assign each event an `incident_domain` via keyword-based classification (hardware, physical_link, stp_topology, routing, authentication, security, configuration, service, inventory).

#### Stage 4b — Pairwise Compatibility Scoring
For every pair of events within a 30-minute window (`MAX_PLAUSIBLE_INCIDENT_SPAN = 1800s`), compute a symmetric compatibility score:

| Signal | Score Contribution | Description |
|--------|-------------------|-------------|
| Topology edge (Tier 1) | +0.40 | Direct neighbor in inferred topology |
| 2-hop topology path | +0.20 | Indirect neighbor |
| Same device | +0.15 | Events from same host |
| Explicit cross-reference | +0.30 | Log content references the other device's IP |
| Shared STP instance (different ports) | +0.50 | Domino pattern across ports on same switch |
| Different ports, same device (no STP) | −0.30 | Penalty to prevent false grouping |
| Shared VLAN/subnet | +0.20 | Network segment co-membership |
| Shared interface | +0.15 | Same port referenced |
| Shared MAC | +0.15 | Same client MAC |
| Same domain | +0.20 | Both events in same domain (e.g., routing) |
| Compatible domains | +0.10 | Cross-domain but causally plausible (e.g., hardware → physical_link) |
| Physical↔Routing without shared identifier | −0.10 | Prevents coincidental sweeps |
| Temporal decay | +0.00–0.10 | Linear decay from 0 to 30 min |
| Historical subtype co-occurrence | +0.15 | Known patterns (e.g., interface_down + bgp) |

Edges with score ≥ `COMPAT_THRESHOLD` (0.40) are added to the compatibility graph.

#### Stage 4c — Louvain Community Detection
Run `nx.community.louvain_communities()` with `resolution=0.8` on each connected component of the compatibility graph. Each community becomes one incident. Isolated nodes (no compatible neighbors) become singleton incidents.

#### Stage 4d — Incident Building
Communities are sorted by earliest event time, assigned `INC-XXXX` IDs, deduplicated (by device+domain+subtype+interface+message prefix), and decorated with metadata (start/end time, duration, device list, domain).

**Deduplication key:** `(device, incident_domain, subtype, interface_id, message[:150])` — the 150-character threshold was raised from 80 to prevent incorrectly deduplicating logs that share a common prefix but have different payloads (e.g., BGP state transitions).

---

### Stage 5 — Causal Inference & Root-Cause Analysis

**File:** [`causalInference/causalInference.py`](causalInference/causalInference.py)

**Purpose:** Within each incident, build a directed causal graph (DAG) and identify the most probable root cause.

#### Event Subtype Classification
Each event is re-classified using keyword matching on the concatenated text of all fields. This provides a normalized subtype (`power`, `bgp`, `ospf`, `interface_down`, etc.) independent of how Stage 1 classified it.

#### 5-Tier Network Domain Model

| Layer | Domain | Subtypes |
|-------|--------|----------|
| 0 | Hardware | `power`, `fan` |
| 1 | Physical | `crc_errors`, `interface_down`, `interface_up`, `transceiver` |
| 2 | Switching/VXLAN Overlay | `stp_topology_change`, `vlan`, `lldp`, `dot1x_failure`, `vni_create`, `vtep_down` |
| 3 | Routing/VXLAN Underlay | `ospf`, `bgp`, `config_change`, `tunnel_nexthop_*` |
| 4 | Security/Management | `ssh_bruteforce`, `admin_auth_failure`, `snmp`, `ntp` |

#### Causal Pair Definitions
The `relation()` function scores directed edges between event pairs. A key component is the **causal pairs dictionary** which encodes known cause→effect relationships:

```
power           → {fan, interface_down, crc_errors}
crc_errors      → {interface_down, stp_topology_change, ospf, bgp}
interface_down  → {stp_topology_change, ospf, bgp, dot1x_failure, tunnel_nexthop_delete, vtep_down}
stp_topology_change → {ospf, bgp, interface_down}
config_change   → {interface_down, stp_topology_change, ospf, bgp, dot1x_failure}
authentication  → {config_change, bgp, ospf, interface_down, stp_topology_change}
bgp             → {ospf}
ospf            → {bgp}
(VXLAN chain)   → tunnel_nexthop_delete → tunnel_activating → tunnel_nexthop_add → tunnel_operational → vtep_operational
```

#### Relation Scoring

| Signal | Score | Description |
|--------|-------|-------------|
| Same device | +0.15 | |
| Same port | +0.35 | |
| Known causal pair | +0.45 | `sa → sb` exists in pairs dict |
| Shared IP reference | +0.35 | Cross-device IP correlation |
| Shared tunnel IP | +0.10 | VXLAN tunnel endpoint match |
| Same incident domain | +0.20 | |
| Layer propagation (lower→higher) | +0.20 | |
| Layer reversal (higher→lower) | −0.15 | |
| Lag ≤ 300s | +0.15 | |
| Lag ≤ 900s | +0.08 | |
| No strong signal | −0.25 | Penalty for purely circumstantial edges |
| **Threshold** | **0.45** | Edges below this are discarded |

#### Backward-Time Inference
For systemic lagging indicators (`radius_failure`, `bgp`, `ospf`), the engine allows up to 120 seconds of backward time — these events are sometimes logged slightly after the effect they're responding to.

#### Root-Cause Scoring
Each event receives a `root_score` combining:
- **Base score** from subtype priority (hardware scores highest: power=130, crc=120)
- **Severity multiplier** (+8 per severity level)
- **Infrastructure boost** (+40 for hardware/physical, +25 for routing)
- **Keyword boost** (+15 for "failure"/"down", +12 for "crc"/"error") — only applied to infrastructure events
- **Security noise penalty** (−60 for SSH brute-force, admin auth failures)
- **Recovery penalty** (−60 for events containing "established", "up", "on-line")
- **Early-timeline bonus** (+0.3 per position from end)

#### Recovery Event Handling
Recovery events are explicitly excluded from the causal DAG construction. They are identified by matching subtypes against `RECOVERY_EVENTS` combined with `RECOVERY_KEYWORDS` (e.g., "established", "up", "on-line", "operational"). This prevents recovery events from being selected as root causes or creating spurious causal edges, while still keeping them available for incident context.

---

### Stage 6 — Validation & Incident Splitting

**File:** [`causalInference/causalInference.py`](causalInference/causalInference.py) → `validate_and_split()`

**Purpose:** After Stage 5 builds the causal DAG for an incident, check whether the graph is fully connected. If there are **disconnected causal components**, the incident is split into sub-incidents (`INC-0002-1`, `INC-0002-2`, etc.).

**Recovery re-attachment:** After splitting, recovery events are re-attached to the sub-component that shares their `device` and `port`, ensuring they appear in the correct incident's timeline without corrupting the DAG.

---

### Stage 7 — Report Generation

**Files:** [`network_incident_summarizer.py`](network_incident_summarizer.py), [`generate_pdf_report.py`](generate_pdf_report.py), [`integrated_pipeline.py`](integrated_pipeline.py)

**Outputs:**
- **`incident_report.md`** — LLM-generated narrative report (if `GEMINI_API_KEY` is set), otherwise a deterministic fallback report with executive summary, root causes, and recommendations.
- **`incident_visualization.html`** — Styled HTML table of all incidents with timing, device, and primary issue columns.
- **`incident_report.pdf`** — Professional PDF with cover page, executive summary, per-incident analysis, causal chain diagrams, and recommendations. Uses ReportLab with a two-pass canvas for consistent page numbering.

---

## Data Flow

```
input.log
  │
  ├─► schema_output.json          (Stage 1: Structured events)
  ├─► preprocessed_events.json    (Stage 2: Flat, skew-corrected)
  ├─► normalized_events.json      (Stage 2: Alias for compatibility)
  ├─► topology_graph.json         (Stage 3: Device connectivity)
  ├─► timeline_output.json        (Stage 4: Incident-partitioned events)
  ├─► causal_inference_output.json(Stage 5-6: Root cause + causal links)
  ├─► incident_report.md          (Stage 7: Narrative report)
  ├─► incident_report.pdf         (Stage 7: PDF report)
  └─► incident_visualization.html (Stage 7: HTML dashboard)
```

---

## Key Design Decisions

### 1. Topology-First Grouping (vs. Time-Window Clustering)
The previous architecture used time-window proximity as the primary grouping signal. This caused **incident merging errors** when unrelated events happened close in time (e.g., an admin login at 14:00 swept into an interface flap at 14:52). The current design inverts this: shared identifiers and topology are primary; time is secondary.

### 2. Explicit Causal Pair Dictionary
Rather than relying solely on statistical correlation or LLM reasoning, the causal engine uses a manually curated dictionary of known cause→effect relationships. This makes the system **deterministic and auditable** — every causal edge can be traced back to a specific rule.

### 3. Recovery Event Exclusion from DAG
Recovery events (interface coming back up, BGP re-establishing) are kept for **context** but excluded from the causal DAG. This prevents:
- Recovery events being selected as root causes
- Spurious causal cycles (down→up→down)
- Recovery events displacing legitimate failure events in scoring

### 4. Cross-Port Isolation with STP Exception
Events on different ports of the same device are penalized (−0.30 compatibility, −0.20 causal) to prevent auth failures on port 1/1/8 from being grouped with interface failures on port 1/1/1. The exception: if both events share the same STP instance (e.g., "Instance 0"), they get a +0.50 bonus, correctly capturing domino patterns where a physical failure on one port triggers STP reconvergence affecting other ports.

### 5. Security Noise Suppression
SSH brute-force attempts and admin auth failures receive aggressive scoring penalties (−60 root score, −0.25 causal edge penalty). These events are almost never the initiating cause of infrastructure outages and are typically either independent noise or a consequence of service disruption.

---

## Event Classification Reference

| Subtype | Domain | Base Score | Layer | Example Log Pattern |
|---------|--------|------------|-------|---------------------|
| `power` | Hardware | 130 | 0 | `Power supply 2 failure` |
| `fan` | Hardware | 110 | 0 | `Fan tray warning` |
| `crc_errors` | Physical | 120 | 1 | `Excessive CRC errors on port 1/1/7` |
| `interface_down` | Physical | 115 | 1 | `Port 1/1/1 is now off-line` |
| `stp_topology_change` | Switching | 85 | 2 | `Topology change detected on port 1/1/30` |
| `ospf` | Routing | 95 | 3 | `OSPF neighbor 192.168.3.1 state changed from Full to Down` |
| `bgp` | Routing | 80 | 3 | `BGP peer 192.168.1.10 state changed from Established to Active` |
| `dot1x_failure` | Switching | 30 | 2 | `802.1x: Authentication failed for client` |
| `ssh_bruteforce` | Security | 25 | 4 | `SSH login failed from IP 203.0.113.5` |
| `config_change` | Routing | 60 | 3 | `Configured from console by admin` |
| `tunnel_nexthop_delete` | VXLAN Underlay | 95 | 3 | `Nexthop delete 9.9.9.9` |

---

## Getting Started

### Prerequisites

```bash
pip install -r requirements.txt
```

Required packages: `networkx`, `python-dotenv`, `python-dateutil`, `reportlab`

### Run the Full Pipeline

```bash
# With LLM report generation (requires GEMINI_API_KEY in .env)
python integrated_pipeline.py --input logs.txt --output-dir pipeline_output

# Without LLM (deterministic only — no API keys needed)
python integrated_pipeline.py --input logs.txt --output-dir pipeline_output --no-llm
```

### Supported Input Formats

| Format | Extension | Description |
|--------|-----------|-------------|
| Raw syslog | `.txt`, `.log` | One syslog line per line (BSD or HPE format) |
| Pre-structured JSON | `.json` | List of nested `{event, device, network, timestamps, raw}` objects |

### Run as Upload API

```bash
python app.py
```

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/analyze` | POST | Upload a log file (multipart `file` field) |

```bash
curl -X POST "http://localhost:8000/analyze" -F "file=@logs.txt"
curl -X POST "http://localhost:8000/analyze?no_llm=true" -F "file=@logs.txt"
```

### Run the Streamlit UI

```bash
streamlit run streamlit_app.py
```

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `GEMINI_API_KEY` | No | Enables LLM-generated narrative reports |
| `GROQ_API` | No | Enables Groq-powered causal reasoning |
| `GROQ_MODEL` | No | Groq model name (default: `llama-3.3-70b-versatile`) |
| `DISABLE_GROQ_REASONING` | No | Set to `1` to disable Groq even if key is present |

---

## Output Artifacts

| File | Stage | Description |
|------|-------|-------------|
| `schema_output.json` | 1 | Structured events in nested schema format |
| `preprocessed_events.json` | 2 | Flat events with corrected timestamps |
| `normalized_events.json` | 2 | Alias of preprocessed events for backward compatibility |
| `topology_graph.json` | 3 | Inferred device connectivity graph (nodes + weighted edges) |
| `timeline_output.json` | 4 | Events grouped into incidents via Louvain partitioning |
| `causal_inference_output.json` | 5-6 | Root causes, causal links, causal sequences, split incidents |
| `incident_report.md` | 7 | Narrative investigation report |
| `incident_report.pdf` | 7 | Professional PDF report with cover page |
| `incident_visualization.html` | 7 | HTML dashboard table |
