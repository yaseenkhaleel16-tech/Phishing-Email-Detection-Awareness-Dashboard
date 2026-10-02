"""Train + compare Logistic Regression, Naive Bayes and Random Forest on TF-IDF features.
Run from the project root:  python -m ml.train_model
"""
import os
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score)
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import make_pipeline

from ml.text import build_text

DATA = "data/phishing_email_dataset.csv"
MODEL_PATH = "models/phishing_model.joblib"


def load():
    df = pd.read_csv(DATA).fillna("").drop_duplicates(subset=["subject", "body"])
    X = [build_text(r.sender, r.subject, r.body, r.attachment_name) for r in df.itertuples()]
    y = (df["label"] == "PHISHING").astype(int).values
    return X, y


def metrics(y, pred):
    return {"accuracy": accuracy_score(y, pred), "precision": precision_score(y, pred, zero_division=0),
            "recall": recall_score(y, pred, zero_division=0), "f1": f1_score(y, pred, zero_division=0)}


def main():
    X, y = load()
    Xtr, Xtmp, ytr, ytmp = train_test_split(X, y, test_size=0.30, stratify=y, random_state=42)
    Xva, Xte, yva, yte = train_test_split(Xtmp, ytmp, test_size=0.50, stratify=ytmp, random_state=42)
    candidates = {
        "LogisticRegression": LogisticRegression(max_iter=500, class_weight="balanced"),
        "NaiveBayes": MultinomialNB(),
        "RandomForest": RandomForestClassifier(n_estimators=150, random_state=42),
    }
    best, best_f1, table = None, -1, {}
    for name, clf in candidates.items():
        pipe = make_pipeline(TfidfVectorizer(ngram_range=(1, 2), min_df=2), clf).fit(Xtr, ytr)
        m = metrics(yva, pipe.predict(Xva)); table[name] = m
        print(f"{name:20s} val: " + "  ".join(f"{k}={v:.3f}" for k, v in m.items()))
        if m["f1"] > best_f1:
            best, best_f1, best_name = pipe, m["f1"], name
    pred = best.predict(Xte)
    print(f"\nBest model: {best_name}\nTEST metrics:", {k: round(v, 3) for k, v in metrics(yte, pred).items()})
    cm = confusion_matrix(yte, pred)
    print("Confusion matrix [[TN FP][FN TP]]:\n", cm)
    os.makedirs("models", exist_ok=True); os.makedirs("reports", exist_ok=True)
    joblib.dump(best, MODEL_PATH)
    try:
        import matplotlib; matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        fig, ax = plt.subplots(figsize=(4, 3.5))
        ax.imshow(cm, cmap="Blues")
        for (i, j), v in __import__("numpy").ndenumerate(cm):
            ax.text(j, i, v, ha="center", va="center")
        ax.set_xticks([0, 1], ["Legit", "Phish"]); ax.set_yticks([0, 1], ["Legit", "Phish"])
        ax.set_xlabel("Predicted"); ax.set_ylabel("Actual"); ax.set_title(best_name)
        fig.tight_layout(); fig.savefig("reports/confusion_matrix.png", dpi=150)
        print("Saved reports/confusion_matrix.png")
    except ImportError:
        print("matplotlib not installed - skipped confusion matrix image")


if __name__ == "__main__":
    main()
