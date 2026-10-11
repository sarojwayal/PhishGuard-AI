"""
PhishGuard AI - Flask backend (DEMONSTRATION MODE)

Run with:   python app.py
Then open:  http://127.0.0.1:5000
"""
import json
import os
import secrets
import sqlite3
import uuid

from flask import (Flask, abort, redirect, render_template, request,
                   send_from_directory, url_for)

from analyzer import BRANDS, build_report, normalize_url
from vision import analyze_screenshot, save_screenshot

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
DB_PATH = os.path.join(BASE_DIR, "phishguard.db")
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(16))  # never hard-code secrets
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024                    # 5 MB upload limit


# ------------------------------------------------------------------ database
def db_run(sql, args=(), commit=False):
    """Run one SQL command and return all rows."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(sql, args).fetchall()
        if commit:
            conn.commit()
        return rows
    finally:
        conn.close()


db_run("""CREATE TABLE IF NOT EXISTS scans (
              id TEXT PRIMARY KEY, url TEXT NOT NULL, created TEXT NOT NULL,
              score INTEGER NOT NULL, category TEXT NOT NULL, report TEXT NOT NULL)""",
       commit=True)


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


# -------------------------------------------------------------------- pages
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scanner")
def scanner():
    return render_template("scanner.html", brands=BRANDS, form={}, error=None)


@app.route("/scan", methods=["POST"])
def scan():
    form = request.form
    brand = form.get("brand", "")
    brand = brand if brand in BRANDS else ""
    page_text = form.get("page_text", "")[:3000]

    def fail(message):
        return render_template("scanner.html", brands=BRANDS, form=form, error=message), 400

    # 1. validate the URL
    try:
        url, assumed = normalize_url(form.get("url", ""))
    except ValueError as err:
        return fail(str(err))

    # 2. validate and save the optional screenshot
    filename, image_info = None, None
    upload = request.files.get("screenshot")
    if upload and upload.filename:
        try:
            filename, path = save_screenshot(upload, UPLOAD_DIR)
            image_info = analyze_screenshot(path)
        except ValueError as err:
            return fail(str(err))

    # 3. build and store the report
    scan_id = "PG-" + uuid.uuid4().hex[:8].upper()
    report = build_report(scan_id, url, assumed, brand, page_text, filename, image_info)
    db_run("INSERT INTO scans (id, url, created, score, category, report) VALUES (?,?,?,?,?,?)",
           (scan_id, url, report["scan"]["created"], report["overall"]["score"],
            report["overall"]["category"], json.dumps(report)), commit=True)
    return redirect(url_for("report", scan_id=scan_id))


@app.route("/report/<scan_id>")
def report(scan_id):
    rows = db_run("SELECT report FROM scans WHERE id = ?", (scan_id,))
    if not rows:
        abort(404)
    return render_template("report.html", r=json.loads(rows[0]["report"]))


@app.route("/dashboard")
def dashboard():
    rows = db_run("SELECT id, url, created, score, category FROM scans ORDER BY created DESC")
    counts = {"Low": 0, "Medium": 0, "High": 0}
    for row in rows:
        counts[row["category"]] += 1
    last = list(reversed(rows[:10]))
    stats = {
        "total": len(rows), "counts": counts,
        "average": round(sum(r["score"] for r in rows) / len(rows)) if rows else 0,
        "chart_labels": [r["id"] for r in last],
        "chart_scores": [r["score"] for r in last],
    }
    return render_template("dashboard.html", stats=stats, recent=rows[:10])


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/uploads/<path:filename>")
def uploads(filename):
    """Serve saved screenshots (they are plain images, never executed)."""
    return send_from_directory(UPLOAD_DIR, filename)


# ------------------------------------------------------------------- errors
@app.errorhandler(404)
def not_found(_):
    return render_template("error.html", title="Page not found",
                           message="We could not find what you were looking for."), 404


@app.errorhandler(413)
def too_large(_):
    return render_template("error.html", title="File too large",
                           message="Screenshots must be smaller than 5 MB."), 413


@app.errorhandler(500)
def server_error(_):
    return render_template("error.html", title="Something went wrong",
                           message="An unexpected error occurred. Please try again."), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)