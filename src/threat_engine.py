def calculate_threat_score(
    ml_score,
    url_score=0,
    sender_score=0,
    vt_score=0,
    header_score=0
):
    """
    Calculates a weighted threat score.
    
    Weights:
    - ML/NLP Confidence: 30%
    - URL Analysis: 25%
    - Sender Reputation: 15%
    - VirusTotal Reputation: 15%
    - Header/Protocol Security (SPF/DMARC): 15%
    """
    
    final_score = (
        ml_score * 0.30 +
        url_score * 0.25 +
        sender_score * 0.15 +
        vt_score * 0.15 +
        header_score * 0.15
    )

    return round(final_score, 2)