"""PhishGuard Flask backend. URLs are analysed as text only - never visited."""
import os, sqlite3, subprocess, sys
from datetime import datetime
from urllib.parse import urlparse
import joblib
import numpy as np
from flask import Flask, jsonify, render_template, request
from feature_extraction import (extract_features, to_vector, normalize_url,
                                FEATURE_NAMES, FEATURE_LABELS)

BASE = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE, "model", "phishing_model.pkl")
ON_VERCEL = bool(os.environ.get("VERCEL"))
# Vercel only allows writing to /tmp (temporary, may reset between requests).
DB_PATH = "/tmp/scans.db" if ON_VERCEL else os.path.join(BASE, "database", "scans.db")
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
app = Flask(__name__)

if not os.path.exists(MODEL_PATH):
    if ON_VERCEL:
        raise RuntimeError("model/phishing_model.pkl is missing - commit it to GitHub.")
    subprocess.check_call([sys.executable, os.path.join(BASE, "train_model.py")])
bundle = joblib.load(MODEL_PATH)
pipeline = bundle["pipeline"]
importances = dict(zip(FEATURE_NAMES, pipeline.named_steps["rf"].feature_importances_))


def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


with db() as con:
    con.execute("""CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT, scanned_at TEXT, prediction TEXT, risk TEXT, confidence REAL)""")


def validate(raw):
    if not isinstance(raw, str) or not raw.strip():
        return None, "Enter a URL to scan."
    raw = raw.strip()
    if len(raw) > 2048 or any(c.isspace() for c in raw):
        return None, "That URL is too long or contains spaces."
    url = normalize_url(raw)
    try:
        p = urlparse(url)
        host = p.hostname
        p.port
    except ValueError:
        return None, "That URL could not be parsed."
    if p.scheme not in ("http", "https") or not host or "." not in host:
        return None, "Enter a full web address such as https://example.com/login."
    return url, None


def flagged(f):
    """Features that raised the warning, ranked by model importance."""
    checks = {"url_length": f["url_length"] > 75, "num_dots": f["num_dots"] > 4,
              "num_hyphens": f["num_hyphens"] > 2, "num_special_chars": f["num_special_chars"] > 4,
              "has_ip": f["has_ip"], "has_https": not f["has_https"],
              "num_subdomains": f["num_subdomains"] > 2, "suspicious_words": f["suspicious_words"] > 0,
              "is_shortener": f["is_shortener"], "has_at_symbol": f["has_at_symbol"],
              "unusual_port": f["unusual_port"], "suspicious_pattern": f["suspicious_pattern"]}
    out = [{"feature": FEATURE_LABELS[k], "value": f[k], "importance": round(importances[k], 3)}
           for k, hit in checks.items() if hit]
    return sorted(out, key=lambda x: -x["importance"])


@app.route("/")
def index():
    return render_template("index.html")


@app.post("/api/scan")
def scan():
    data = request.get_json(silent=True) or {}
    url, err = validate(data.get("url"))
    if err:
        return jsonify({"error": err}), 400
    f = extract_features(url)
    X = np.array([to_vector(f)], dtype=float)
    p_phish = float(pipeline.predict_proba(X)[0][1])
    is_phish = p_phish >= 0.5
    risk = "High" if p_phish >= 0.65 else "Medium" if p_phish >= 0.35 else "Low"
    confidence = round((p_phish if is_phish else 1 - p_phish) * 100, 1)
    pred = "Potentially Phishing" if is_phish else "Legitimate"
    reasons = flagged(f)
    if is_phish:
        explanation = ("The model found a URL structure that resembles known phishing patterns."
                       + (f" Main signals: {', '.join(r['feature'].lower() for r in reasons[:3])}." if reasons else ""))
    elif reasons:
        explanation = "The URL looks mostly normal, but a few minor signals were noted. Stay cautious."
    else:
        explanation = "No common phishing signals were found in the URL structure."
    with db() as con:
        con.execute("INSERT INTO scans (url, scanned_at, prediction, risk, confidence) VALUES (?,?,?,?,?)",
                    (url, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), pred, risk, confidence))
    return jsonify({"url": url, "prediction": pred, "risk": risk, "confidence": confidence,
                    "phishing_probability": round(p_phish * 100, 1), "contributing_features": reasons,
                    "features": f, "explanation": explanation})


@app.get("/api/history")
def history():
    with db() as con:
        rows = con.execute("SELECT url, scanned_at, prediction, risk, confidence FROM scans ORDER BY id DESC LIMIT 200").fetchall()
    return jsonify([dict(r) for r in rows])


@app.delete("/api/history")
def clear_history():
    with db() as con:
        con.execute("DELETE FROM scans")
    return jsonify({"cleared": True})


@app.get("/api/stats")
def stats():
    with db() as con:
        total = con.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        safe = con.execute("SELECT COUNT(*) FROM scans WHERE prediction='Legitimate'").fetchone()[0]
    return jsonify({"total": total, "safe": safe, "suspicious": total - safe})


if __name__ == "__main__":
    app.run(debug=True)
