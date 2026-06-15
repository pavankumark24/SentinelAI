def map_to_mitre(
    indicators,
    url_results,
    sender_result
):

    techniques = []

    joined = str(indicators)

    if "Credential" in joined:

        techniques.append(
            "T1566.002 - Phishing: Spearphishing Link"
        )

    if url_results:

        techniques.append(
            "T1583 - Acquire Infrastructure"
        )

    if sender_result.get("score",0) > 30:

        techniques.append(
            "T1656 - Impersonation"
        )

    return list(set(techniques))