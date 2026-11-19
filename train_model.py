import json
from datetime import date
import os

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB

from utils.preprocessing import clean_text


BASE_DIRECTORY = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(BASE_DIRECTORY, "dataset", "spam_dataset.csv")
MODEL_DIRECTORY = os.path.join(BASE_DIRECTORY, "models")
MODEL_PATH = os.path.join(MODEL_DIRECTORY, "spam_model.pkl")
METRICS_PATH = os.path.join(MODEL_DIRECTORY, "metrics.json")


def train_model():
    dataset = pd.read_csv(DATASET_PATH)
    dataset["clean_text"] = dataset["text"].apply(clean_text)

    training_text, test_text, training_labels, test_labels = train_test_split(
        dataset["clean_text"],
        dataset["label"],
        test_size=0.20,
        random_state=42,
        stratify=dataset["label"],
    )

    vectorizer = TfidfVectorizer(ngram_range=(1, 2), min_df=2)
    training_features = vectorizer.fit_transform(training_text)
    test_features = vectorizer.transform(test_text)

    classifier = MultinomialNB()
    classifier.fit(training_features, training_labels)
    predicted_labels = classifier.predict(test_features)

    metrics = {
        "accuracy": float(accuracy_score(test_labels, predicted_labels)),
        "precision": float(precision_score(test_labels, predicted_labels, pos_label="spam", zero_division=0)),
        "recall": float(recall_score(test_labels, predicted_labels, pos_label="spam", zero_division=0)),
        "f1": float(f1_score(test_labels, predicted_labels, pos_label="spam", zero_division=0)),
        "confusion_matrix": confusion_matrix(
            test_labels, predicted_labels, labels=["ham", "spam"]
        ).tolist(),
        "dataset_size": int(len(dataset)),
        "training_date": date.today().isoformat(),
    }

    print("Accuracy:", metrics["accuracy"])
    print("Precision:", metrics["precision"])
    print("Recall:", metrics["recall"])
    print("F1:", metrics["f1"])
    print("Confusion Matrix:")
    print(metrics["confusion_matrix"])

    os.makedirs(MODEL_DIRECTORY, exist_ok=True)
    joblib.dump({"vectorizer": vectorizer, "classifier": classifier}, MODEL_PATH)
    with open(METRICS_PATH, "w", encoding="utf-8") as metrics_file:
        json.dump(metrics, metrics_file, indent=4)

    print("Saved model:", MODEL_PATH)
    print("Saved metrics:", METRICS_PATH)


# To retrain after editing the dataset, run: python make_dataset.py && python train_model.py
if __name__ == "__main__":
    train_model()