from src.predict import predict_email

email = """
Your account has been suspended.
Click here to verify your credentials.
"""

print(predict_email(email))