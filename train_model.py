"""Builds a DEMONSTRATION dataset (if none exists), trains a Random Forest,
evaluates it and saves it with Joblib.  Run:  python train_model.py

WARNING: dataset/phishing_dataset.csv is synthetic. Replace it with a real
labelled dataset (columns: url,label  where label 1 = phishing) to get a
meaningful model. Scores on synthetic data say nothing about real-world accuracy.
"""
import os, random
import joblib, numpy as np, pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from feature_extraction import extract_features, FEATURE_NAMES, to_vector

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(BASE, "dataset", "phishing_dataset.csv")
MODEL = os.path.join(BASE, "model", "phishing_model.pkl")
random.seed(42); np.random.seed(42)

LEGIT = ["google.com", "wikipedia.org", "github.com", "amazon.com", "bbc.co.uk", "nytimes.com",
         "microsoft.com", "apple.com", "stackoverflow.com", "mozilla.org", "python.org",
         "linkedin.com", "reddit.com", "netflix.com", "paypal.com", "ebay.com", "nasa.gov",
         "mit.edu", "cloudflare.com", "dropbox.com", "spotify.com", "adobe.com"]
BRANDS = ["paypal", "amazon", "apple", "microsoft", "netflix", "google", "facebook", "sbi", "hdfcbank", "dhl"]
WORDS = ["login", "verify", "secure", "update", "account", "signin", "confirm", "banking"]
TLDS = ["tk", "ml", "xyz", "top", "click", "ga", "cf", "com", "net", "info"]
rnd = lambda n: "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=n))


def legit_url():
    d = random.choice(LEGIT)
    sub = random.choice(["", "", "www.", "www.", "docs.", "support.", "mail."])
    path = random.choice(["", "/", "/" + rnd(6), "/about", "/news/" + rnd(8), "/search?q=" + rnd(5),
                          "/products/" + rnd(5) + "-" + rnd(4), "/account/settings", "/login"])
    scheme = "https" if random.random() < 0.93 else "http"
    return f"{scheme}://{sub}{d}{path}"


def phish_url():
    b, w, t = random.choice(BRANDS), random.choice(WORDS), random.choice(TLDS)
    k = random.randint(0, 7)
    scheme = "http" if random.random() < 0.7 else "https"
    if k == 0: return f"{scheme}://{b}-{w}.{rnd(6)}.{t}/{w}/{rnd(8)}"
    if k == 1: return f"{scheme}://{b}.com.{w}-{rnd(5)}.{t}/{w}.php?id={rnd(10)}"
    if k == 2: return f"http://{'.'.join(str(random.randint(1, 254)) for _ in range(4))}/{b}/{w}/index.html"
    if k == 3: return f"{scheme}://{b}.com@{rnd(7)}.{t}/{w}"
    if k == 4: return f"{scheme}://{w}.{b}.{rnd(4)}-{rnd(4)}.{t}:{random.choice([8080, 8443, 2083])}/{w}"
    if k == 5: return f"https://{random.choice(['bit.ly', 'tinyurl.com', 'cutt.ly'])}/{rnd(6)}"
    if k == 6: return f"{scheme}://secure-{b}-{w}-{rnd(4)}.{t}/%{random.randint(20, 99)}{rnd(12)}"
    return f"{scheme}://{rnd(5)}.{b}.{rnd(5)}.{t}/{w}/{rnd(6)}?session={rnd(16)}"


def build_dataset(n=2000):
    rows = [(legit_url(), 0) for _ in range(n // 2)] + [(phish_url(), 1) for _ in range(n // 2)]
    df = pd.DataFrame(rows, columns=["url", "label"])
    flip = df.sample(frac=0.03, random_state=1).index          # 3% label noise
    df.loc[flip, "label"] = 1 - df.loc[flip, "label"]
    df = df.sample(frac=1, random_state=7).reset_index(drop=True)
    os.makedirs(os.path.dirname(DATA), exist_ok=True)
    df.to_csv(DATA, index=False)
    return df


def main():
    if os.path.exists(DATA):
        df = pd.read_csv(DATA)
    else:
        print("No dataset found -> generating SYNTHETIC demonstration dataset.")
        df = build_dataset()
    df = df.dropna().drop_duplicates("url")
    X = pd.DataFrame([to_vector(extract_features(u)) for u in df["url"]], columns=FEATURE_NAMES)
    y = df["label"].astype(int)
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    pipe = Pipeline([("scale", StandardScaler()),
                     ("rf", RandomForestClassifier(n_estimators=200, max_depth=12,
                                                   random_state=42, n_jobs=-1))])
    pipe.fit(Xtr.values, ytr)
    pred = pipe.predict(Xte.values)
    metrics = {"accuracy": accuracy_score(yte, pred), "precision": precision_score(yte, pred),
               "recall": recall_score(yte, pred), "f1": f1_score(yte, pred)}
    for k, v in metrics.items(): print(f"{k:>9}: {v:.3f}")
    print("NOTE: scores are on a demonstration dataset and do NOT reflect real-world accuracy.")
    os.makedirs(os.path.dirname(MODEL), exist_ok=True)
    joblib.dump({"pipeline": pipe, "features": FEATURE_NAMES, "metrics": metrics}, MODEL)
    print("Saved model ->", MODEL)


if __name__ == "__main__":
    main()
