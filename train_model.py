import os

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB

from utils.preprocessing import clean_text


BASE_DIRECTORY = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(BASE_DIRECTORY, "dataset", "spam_dataset.csv")
MODEL_DIRECTORY = os.path.join(BASE_DIRECTORY, "models")
MODEL_PATH = os.path.join(MODEL_DIRECTORY, "spam_model.pkl")


def train_model():
    dataset = pd.read_csv(DATASET_PATH)
    dataset["clean_text"] = dataset["text"].apply(clean_text)

    stratification = (
        dataset["label"].astype(str) + "::" + dataset["language"].astype(str)
    )
    (
        training_text,
        test_text,
        training_labels,
        test_labels,
        _,
        test_languages,
    ) = train_test_split(
        dataset["clean_text"],
        dataset["label"],
        dataset["language"],
        test_size=0.20,
        random_state=42,
        stratify=stratification,
    )

    vectorizer_candidates = [
        ("word", TfidfVectorizer(ngram_range=(1, 2), min_df=2)),
        (
            "char_wb",
            TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), min_df=2),
        ),
    ]
    evaluations = []

    for vectorizer_name, vectorizer in vectorizer_candidates:
        training_features = vectorizer.fit_transform(training_text)
        test_features = vectorizer.transform(test_text)
        classifier = MultinomialNB()
        classifier.fit(training_features, training_labels)
        predicted_labels = classifier.predict(test_features)
        overall_metrics = _get_metrics(test_labels, predicted_labels)

        print("Vectorizer:", vectorizer_name)
        _print_metrics("Overall", overall_metrics)
        for language in ("en", "hinglish", "hi"):
            language_mask = test_languages == language
            language_metrics = _get_metrics(
                test_labels[language_mask],
                predicted_labels[language_mask.to_numpy()],
            )
            _print_metrics(language, language_metrics)

        evaluations.append(
            (overall_metrics["f1"], vectorizer_name, vectorizer, classifier)
        )

    # Scores are estimates; accuracy depends on dataset size and language coverage.
    # Select the vectorizer with the higher overall F1 on the held-out split.
    _, selected_name, vectorizer, classifier = max(
        evaluations, key=lambda evaluation: evaluation[0]
    )
    print("Selected vectorizer:", selected_name)

    os.makedirs(MODEL_DIRECTORY, exist_ok=True)
    joblib.dump({"vectorizer": vectorizer, "classifier": classifier}, MODEL_PATH)

    print("Saved model:", MODEL_PATH)


def _get_metrics(expected_labels, predicted_labels):
    return {
        "accuracy": accuracy_score(expected_labels, predicted_labels),
        "precision": precision_score(
            expected_labels, predicted_labels, pos_label="spam", zero_division=0
        ),
        "recall": recall_score(
            expected_labels, predicted_labels, pos_label="spam", zero_division=0
        ),
        "f1": f1_score(
            expected_labels, predicted_labels, pos_label="spam", zero_division=0
        ),
    }


def _print_metrics(label, metrics):
    print(
        "{}: Accuracy={:.4f}, Precision={:.4f}, Recall={:.4f}, F1={:.4f}".format(
            label,
            metrics["accuracy"],
            metrics["precision"],
            metrics["recall"],
            metrics["f1"],
        )
    )


# To retrain after editing the dataset, run: python make_dataset.py && python train_model.py
if __name__ == "__main__":
    train_model()