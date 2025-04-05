import os
import time
import json
import io
import requests
from dotenv import load_dotenv
import pandas as pd
from flask import Flask, render_template, request, session, send_file, redirect, url_for
from xhtml2pdf import pisa

load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

API_KEY = os.getenv("API_KEY")
IP_BASE_URL = "https://www.virustotal.com/api/v3/ip_addresses/"
HASH_BASE_URL = "https://www.virustotal.com/api/v3/files/"
HEADERS = {"x-apikey": API_KEY}

UPLOAD_FOLDER = "uploads"
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/check-ip", methods=["GET", "POST"])
def check_ip():
    if request.method == "POST":
        file = request.files["file"]
        if file and file.filename.endswith(".txt"):
            file_path = os.path.join(UPLOAD_FOLDER, file.filename)
            file.save(file_path)
            with open(file_path, "r") as f:
                ips = [line.strip() for line in f if line.strip()]
            results = []
            for ip in ips:
                time.sleep(1)
                response = requests.get(IP_BASE_URL + ip, headers=HEADERS)
                if response.status_code == 200:
                    data = response.json()
                    attributes = data.get("data", {}).get("attributes", {})
                    stats = attributes.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    total = sum(stats.values()) if stats else "N/A"
                    reputation = attributes.get("reputation", "N/A")
                    votes = attributes.get("total_votes", {})
                    isp = attributes.get("as_owner", "Unknown ISP")
                    country = attributes.get("country", "Unknown Country")
                    network = attributes.get("network", "N/A")
                    whois = attributes.get("whois", "N/A")
                    results.append({
                        "type": "IP",
                        "value": ip,
                        "malicious": f"{malicious}/{total}",
                        "reputation": reputation,
                        "votes": votes,
                        "isp": isp,
                        "country": country,
                        "network": network,
                        "whois": whois
                    })
                else:
                    results.append({
                        "type": "IP", "value": ip,
                        "malicious": "Error fetching data",
                        "reputation": "N/A", "votes": {},
                        "isp": "N/A", "country": "N/A",
                        "tags": "N/A", "network": "N/A", "whois": "N/A"
                    })
            session["results"] = json.dumps(results)
            return render_template("results.html", results=results)
    return render_template("ip_check.html")

@app.route("/check-hash", methods=["GET", "POST"])
def check_hash():
    if request.method == "POST":
        file = request.files["file"]
        if file and file.filename.endswith(".txt"):
            file_path = os.path.join(UPLOAD_FOLDER, file.filename)
            file.save(file_path)
            with open(file_path, "r") as f:
                hashes = [line.strip() for line in f if line.strip()]
            results = []
            for hash_value in hashes:
                time.sleep(1)
                response = requests.get(HASH_BASE_URL + hash_value, headers=HEADERS)
                if response.status_code == 200:
                    data = response.json()
                    attributes = data.get("data", {}).get("attributes", {})
                    stats = attributes.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    total = sum(stats.values()) if stats else "N/A"
                    reputation = attributes.get("reputation", "N/A")
                    votes = attributes.get("total_votes", {})
                    file_type = attributes.get("type_description", "Unknown")
                    filename = attributes.get("names", ["Unknown"])[0]
                    results.append({
                        "type": "HASH",
                        "value": hash_value,
                        "malicious": f"{malicious}/{total}",
                        "reputation": reputation,
                        "votes": votes,
                        "file_type": file_type,
                        "filename": filename
                    })
                else:
                    results.append({
                        "type": "HASH", "value": hash_value,
                        "malicious": "Error fetching data",
                        "reputation": "N/A", "votes": {},
                        "file_type": "N/A", "filename": "N/A"
                    })
            session["results"] = json.dumps(results)
            return render_template("results.html", results=results)
    return render_template("hash_check.html")

@app.route("/download-excel")
def download_excel():
    results_json = session.get("results")
    if not results_json:
        return redirect(url_for("home"))

    results = json.loads(results_json)
    for item in results:
        item["harmless_votes"] = item.get("votes", {}).get("harmless", "N/A")
        item["malicious_votes"] = item.get("votes", {}).get("malicious", "N/A")
        item.pop("votes", None)

    df = pd.DataFrame(results)
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
        df.to_excel(writer, index=False, sheet_name="Results")
    output.seek(0)

    return send_file(output, download_name="reputation_results.xlsx", as_attachment=True)

@app.route("/download-pdf")
def download_pdf():
    results_json = session.get("results")
    if not results_json:
        return redirect(url_for("home"))

    results = json.loads(results_json)
    rendered = render_template("pdf_template.html", results=results)
    pdf = io.BytesIO()
    pisa.CreatePDF(io.StringIO(rendered), dest=pdf)
    pdf.seek(0)

    return send_file(pdf, mimetype='application/pdf', download_name='reputation_results.pdf', as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)
