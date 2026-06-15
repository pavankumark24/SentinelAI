from transformers import DistilBertTokenizerFast
from transformers import DistilBertForSequenceClassification

import torch
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

MODEL_PATH = BASE_DIR / "models" / "sentinel_distilbert"

tokenizer = DistilBertTokenizerFast.from_pretrained(MODEL_PATH)

model = DistilBertForSequenceClassification.from_pretrained(MODEL_PATH)

model.eval()


def predict_email_distilbert(email_text):

    inputs = tokenizer(
        email_text,
        return_tensors="pt",
        truncation=True,
        max_length=256,
        padding=True
    )

    with torch.no_grad():
        outputs = model(**inputs)

    probs = torch.softmax(outputs.logits, dim=1)

    phishing_prob = probs[0][1].item()

    prediction = 1 if phishing_prob > 0.5 else 0

    return prediction, phishing_prob
print("LOADED DISTILBERT FILE")