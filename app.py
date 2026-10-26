import csv
import io
import json
import os
import uuid
from datetime import datetime, timezone

from flask import Flask, flash, jsonify, redirect, render_template, request, send_file, session, url_for
from werkzeug.utils import secure_filename

from analyzer import analyze_csv, analyze_pcap
from detector import detect_queries

app = Flask(__name__)
app.secret_key = os.environ.get("DNS_DETECTOR_SECRET", "local-development-key-change-me")
app.config["MAX_CONTENT_LENGTH"] = 15 * 1024 * 1024
ALLOWED_EXTENSIONS = {"csv", "pcap", "pcapng"}
RESULTS = {}

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def current_results():
    result_id = session.get("result_id")
    return RESULTS.get(result_id, {"records": [], "summary": {}, "filename": "No analysis"})

def store_results(records, filename):
    analyzed = detect_queries(records)
    result_id = str(uuid.uuid4())
    summary = {
        "total": len(analyzed),
        "suspicious": sum(1 for item in analyzed if item["risk_score"] >= 30),
        "high": sum(1 for item in analyzed if item["severity"] == "High"),
        "domains": len({item["registered_domain"] for item in analyzed if item["registered_domain"]})
    }
    RESULTS[result_id] = {"records": analyzed, "summary": summary, "filename": filename}
    session["result_id"] = result_id
    return result_id

@app.route("/")
def index():
    result = current_results()
    return render_template("index.html", result=result)

@app.route("/demo", methods=["POST"])
def demo():
    sample_path = os.path.join(app.root_path, "data", "sample_dns.csv")
    try:
        records = analyze_csv(sample_path)
        store_results(records, "sample_dns.csv")
        flash("Sample dataset analyzed successfully.", "success")
    except Exception:
        flash("The sample dataset could not be analyzed. Check that data/sample_dns.csv exists.", "error")
    return redirect(url_for("index"))

@app.route("/upload", methods=["POST"])
def upload():
    file = request.files.get("file")
    if not file or not file.filename:
        flash("Choose a PCAP, PCAPNG, or CSV file first.", "error")
        return redirect(url_for("index"))
    filename = secure_filename(file.filename)
    if not filename or not allowed_file(filename):
        flash("Unsupported file type. Upload a CSV, PCAP, or PCAPNG file.", "error")
        return redirect(url_for("index"))
    extension = filename.rsplit(".", 1)[1].lower()
    raw = file.read()
    if not raw:
        flash("The uploaded file is empty.", "error")
        return redirect(url_for("index"))
    try:
        if extension == "csv":
            records = analyze_csv(io.BytesIO(raw))
        else:
            records = analyze_pcap(io.BytesIO(raw))
        store_results(records, filename)
        flash(f"Analyzed {len(records)} DNS queries from {filename}.", "success")
    except ImportError:
        flash("PCAP analysis requires Scapy. Install dependencies with: pip install -r requirements.txt", "error")
    except (ValueError, UnicodeDecodeError, csv.Error) as exc:
        flash(str(exc), "error")
    except Exception:
        flash("The file could not be analyzed. Verify that it is a valid CSV or packet capture.", "error")
    return redirect(url_for("index"))

@app.route("/results")
def results():
    result = current_results()
    records = result["records"]
    severity = request.args.get("severity", "All")
    search = request.args.get("q", "").strip().lower()
    sort = request.args.get("sort", "risk")
    if severity in {"Low", "Medium", "High"}:
        records = [item for item in records if item["severity"] == severity]
    if search:
        records = [item for item in records if search in item["domain"].lower() or search in item["source_ip"].lower() or search in " ".join(item["reasons"]).lower()]
    if sort == "time":
        records = sorted(records, key=lambda item: item["timestamp"], reverse=True)
    else:
        records = sorted(records, key=lambda item: item["risk_score"], reverse=True)
    return render_template("results.html", result=result, records=records, severity=severity, query=request.args.get("q", ""), sort=sort)

@app.route("/query/<int:index>")
def query_details(index):
    records = current_results()["records"]
    item = next((record for record in records if record.get("record_id") == index), None)
    if item is None:
        flash("That query is not available in the current analysis.", "error")
        return redirect(url_for("results"))
    return render_template("query_details.html", item=item)

@app.route("/api/summary")
def api_summary():
    return jsonify(current_results()["summary"])

@app.route("/export/<format_name>")
def export_results(format_name):
    result = current_results()
    records = result["records"]
    if not records:
        flash("Analyze a dataset before exporting a report.", "error")
        return redirect(url_for("index"))
    if format_name == "json":
        payload = json.dumps(records, indent=2)
        return send_file(io.BytesIO(payload.encode("utf-8")), mimetype="application/json", as_attachment=True, download_name="dns_analysis_report.json")
    if format_name == "csv":
        output = io.StringIO()
        fields = ["timestamp", "source_ip", "destination_ip", "domain", "record_type", "query_length", "entropy", "triggered_rules", "risk_score", "severity", "reasons"]
        writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for item in records:
            row = dict(item)
            row["reasons"] = "; ".join(item["reasons"])
            row["triggered_rules"] = "; ".join(item["triggered_rules"])
            writer.writerow(row)
        return send_file(io.BytesIO(output.getvalue().encode("utf-8")), mimetype="text/csv", as_attachment=True, download_name="dns_analysis_report.csv")
    flash("Unsupported export format.", "error")
    return redirect(url_for("index"))

@app.errorhandler(413)
def too_large(_error):
    flash("File exceeds the 12 MB upload limit.", "error")
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
