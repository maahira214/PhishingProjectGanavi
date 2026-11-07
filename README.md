# PhishGuard – Phishing Website Detector

A beginner-friendly machine learning project. Flask serves a dashboard and API; a scikit-learn Random Forest scores URLs using 12 features extracted from the URL text. **URLs are never opened or visited.**

> **Important:** no real dataset is bundled. `train_model.py` generates a clearly labelled **synthetic demonstration dataset** (`dataset/phishing_dataset.csv`). The model's ~97% test score only shows the pipeline works on that fake data. It is **not** real-world detection accuracy. For real use, replace the CSV with a genuine labelled dataset (columns `url,label`, 1 = phishing) and re-run training.

## Run on Windows
1. Install Python 3.10+ from python.org (tick **Add Python to PATH**).
2. Open Command Prompt in the `phishguard` folder:
```
python -m venv venv
venv\Scripts\activate
pip install -r requirements-train.txt
python train_model.py
python app.py
```
3. Open http://127.0.0.1:5000 in your browser.

(`app.py` trains automatically if `model/phishing_model.pkl` is missing. The dashboard loads Chart.js and fonts from the internet.)

## How the model works
1. `feature_extraction.py` turns a URL into 12 numbers (length, dots, hyphens, special characters, IP host, HTTPS, subdomains, suspicious words, shortener, `@`, unusual port, suspicious patterns). Training and prediction share this exact code.
2. `train_model.py` splits data 80/20, scales features, trains a Random Forest (200 trees), prints accuracy/precision/recall/F1 and saves the model with Joblib.
3. `app.py` loads the model. Each tree votes; the share voting "phishing" is the probability. ≥ 50% = *Potentially Phishing*. Risk: < 35% Low, 35–65% Medium, ≥ 65% High. The "contributing features" are the triggered warning signs ranked by the model's feature importance.

## API
| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/api/scan` | body `{"url": "..."}` – analyse a URL |
| GET | `/api/history` | scan history |
| DELETE | `/api/history` | clear history |
| GET | `/api/stats` | total / safe / suspicious counts |

## Limitations
URL-only features miss content-based attacks, compromised legitimate sites and brand-new tricks. Treat results as a learning aid, not a security guarantee.

## Deploying to Vercel
1. Run `python train_model.py` locally and **commit `model/phishing_model.pkl`** (Vercel cannot train it).
2. Push to GitHub and import the repo in Vercel (no build settings needed; `vercel.json` handles it).
3. Scan history is stored in `/tmp`, so on Vercel it is temporary and may reset between requests.
