from src.distilbert_predict import predict_email_distilbert

email = """
Your account will be suspended.
Verify your password immediately.
Click below.
"""

prediction, confidence = predict_email_distilbert(email)

print(prediction)
print(confidence)