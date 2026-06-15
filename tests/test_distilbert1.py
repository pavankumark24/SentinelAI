from src.distilbert_predict import predict_email_distilbert

email = """
Dear Student,

The semester examination timetable has been published.

Regards,
Examination Cell
"""

prediction, confidence = predict_email_distilbert(email)

print(prediction)
print(confidence)