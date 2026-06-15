from src.distilbert_predict import predict_email_distilbert

email = """
We detected unusual activity in your bank account.

Login immediately to avoid suspension.
"""
prediction, confidence = predict_email_distilbert(email)

print(prediction)
print(confidence)