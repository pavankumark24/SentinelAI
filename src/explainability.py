def explain_score(
    ml_score,
    url_score,
    sender_score,
    vt_score
):

    return {
        "ML Model": round(ml_score * 0.40, 2),
        "URL Analysis": round(url_score * 0.30, 2),
        "Sender Reputation": round(sender_score * 0.15, 2),
        "VirusTotal": round(vt_score * 0.15, 2)
    }