# Networking-Incident-Project-HPE-CPP

## End-to-End Integrated Flow

This project now supports a complete incident workflow where a single input log file triggers:

1. Schema conversion (existing schema_conversion pipeline)
2. Timeline reconstruction
3. Causal inference
4. Final report generation (LLM if GEMINI_API_KEY is available, otherwise deterministic fallback)
5. Visualization report generation (HTML)

## Run From CLI

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the full pipeline:

```bash
python integrated_pipeline.py --input datasetphase1.json --output-dir pipeline_output
```

For text/raw log files:

```bash
python integrated_pipeline.py --input logs.txt --output-dir pipeline_output
```

Disable LLM report generation:

```bash
python integrated_pipeline.py --input datasetphase1.json --output-dir pipeline_output --no-llm
```

## Run As Upload API

Start the API:

```bash
python app.py
```

Endpoints:

- GET /health
- POST /analyze (multipart form-data with field name file)

Example with curl:

```bash
curl -X POST "http://localhost:8000/analyze" \
	-F "file=@datasetphase1.json"
```

To disable LLM report in API call:

```bash
curl -X POST "http://localhost:8000/analyze?no_llm=true" \
	-F "file=@datasetphase1.json"
```

## Output Artifacts

The integrated pipeline writes:

- normalized_events.json
- timeline_output.json
- causal_inference_output.json
- incident_report.md
- incident_visualization.html
