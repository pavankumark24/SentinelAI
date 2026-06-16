from src.distilbert_predict import predict_email_distilbert

email = """
URGENT

Your account will be suspended.

Verify your credentials immediately.

Click below:

https://google.com

Failure to act within 24 hours will result in permanent account termination.
"""

prediction, confidence = predict_email_distilbert(email)

print(prediction)
print(confidence)