import json
import tempfile
from pathlib import Path

from flask import Flask, jsonify, request
from dotenv import load_dotenv

from integrated_pipeline import run_full_pipeline


load_dotenv()


app = Flask(__name__)


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.post("/analyze")
def analyze_logs():
    if "file" not in request.files:
        return jsonify({"error": "file is required"}), 400

    uploaded = request.files["file"]
    if not uploaded.filename:
        return jsonify({"error": "filename is required"}), 400

    suffix = Path(uploaded.filename).suffix.lower()
    if suffix not in {".txt", ".log", ".json"}:
        return jsonify({"error": "supported extensions: .txt, .log, .json"}), 400

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir) / uploaded.filename
        uploaded.save(temp_path)

        output_dir = Path("pipeline_output") / temp_path.stem
        use_llm = request.args.get("no_llm", "false").lower() != "true"

        try:
            result = run_full_pipeline(temp_path, output_dir, use_llm_report=use_llm)
            return jsonify(result)
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)
