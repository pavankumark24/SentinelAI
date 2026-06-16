import joblib
from pathlib import Path
import re


BASE_DIR = Path(__file__).resolve().parent.parent

model = joblib.load(BASE_DIR / "models" / "phishing_model.pkl")
vectorizer = joblib.load(BASE_DIR / "models" / "vectorizer.pkl")


def predict_email(email_text):

    email_vector = vectorizer.transform([email_text])

    prediction = model.predict(email_vector)[0]

    confidence = model.predict_proba(email_vector)[0]

    phishing_prob = confidence[1]

    return prediction, phishing_prob



def get_threat_indicators(email_text):

    indicators = []

    text = email_text.lower()

    if re.search(r"http[s]?://|www\.", text):
        indicators.append("🔗 URL Found")

    urgent_words = [
        "urgent",
        "immediately",
        "verify",
        "suspended",
        "limited time",
        "act now"
    ]

    if any(word in text for word in urgent_words):
        indicators.append("⚠️ Urgent Language Detected")

    credential_words = [
        "password",
        "login",
        "account",
        "credentials"
    ]

    if any(word in text for word in credential_words):
        indicators.append("🔐 Credential Request Detected")

    financial_words = [
        "bank",
        "payment",
        "credit card",
        "transaction"
    ]

    if any(word in text for word in financial_words):
        indicators.append("💰 Financial Keywords Found")

    return indicators