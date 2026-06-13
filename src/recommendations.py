def get_recommendation(score):

    if score < 20:
        return "No immediate threat detected."

    elif score < 40:
        return "Exercise caution before interacting."

    elif score < 70:
        return "Verify sender and avoid clicking links."

    elif score < 90:
        return "Potential phishing attempt. Do not engage."

    else:
        return "Critical threat. Block and report immediately."