def generate_report(
    prediction,
    confidence,
    severity,
    indicators,
    url_results
):

    report = []

    report.append("🛡️ SentinelAI Security Report")
    report.append("")

    report.append(f"Prediction: {prediction}")
    report.append(f"Confidence: {confidence}%")
    report.append(f"OWASP Severity: {severity}")

    report.append("")
    report.append("Threat Indicators:")

    if indicators:

        for item in indicators:
            report.append(f"• {item}")

    else:

        report.append("• None Found")

    report.append("")
    report.append("URL Intelligence:")

    if url_results:

        for result in url_results:

            report.append(
                f"• Domain: {result['domain']}"
            )

            report.append(
                f"  Risk Score: {result['score']}"
            )

            for finding in result["findings"]:

                report.append(
                    f"    - {finding}"
                )

    else:

        report.append("• No URLs Found")

    report.append("")
    report.append("Recommended Actions:")

    if prediction == "PHISHING":

        report.append(
            "• Do not click any links."
        )

        report.append(
            "• Verify sender identity."
        )

        report.append(
            "• Report email to security team."
        )

    else:

        report.append(
            "• No immediate threat detected."
        )

    return "\n".join(report)