from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    PageBreak
)

from reportlab.lib.styles import getSampleStyleSheet


def generate_pdf_report(filename, payload):

    pdf = SimpleDocTemplate(filename)

    styles = getSampleStyleSheet()

    content = []

    content.append(
        Paragraph(
            "SentinelAI Security Assessment Report",
            styles["Title"]
        )
    )

    content.append(Spacer(1, 20))

    content.append(
        Paragraph(
            f"<b>Threat Score:</b> {round(payload['overall_score'],2)}",
            styles["Normal"]
        )
    )

    content.append(
        Paragraph(
            f"<b>Threat Level:</b> {payload['threat_level']}",
            styles["Normal"]
        )
    )

    content.append(
    Paragraph(
        f"<b>Classification:</b> {payload['classification']}",
        styles["Normal"]
    )
)

    content.append(Spacer(1, 20))

    # Executive Summary

    content.append(
        Paragraph(
            "Executive Summary",
            styles["Heading1"]
        )
    )

    content.append(
        Paragraph(
            f"""
            SentinelAI completed a threat assessment and assigned
            a risk score of {round(payload['overall_score'],2)}.
            The communication was classified as
            <b>{payload['threat_level']}</b>.
            """,
            styles["BodyText"]
        )
    )

    content.append(Spacer(1, 12))

    # Indicators

    content.append(
        Paragraph(
            "Threat Indicators",
            styles["Heading1"]
        )
    )

    indicators = payload.get("indicators", [])

    if indicators:
        for item in indicators:
            content.append(
                Paragraph(
                    f"• {item}",
                    styles["BodyText"]
                )
            )
    else:
        content.append(
            Paragraph(
                "No indicators detected.",
                styles["BodyText"]
            )
        )

    content.append(Spacer(1, 12))

    # IOC Section

    content.append(
        Paragraph(
            "Indicators of Compromise",
            styles["Heading1"]
        )
    )

    iocs = payload.get("iocs", {})

    for category in ["domains", "urls", "ips", "emails"]:

        values = iocs.get(category, [])

        if values:

            content.append(
                Paragraph(
                    f"<b>{category.upper()}</b>",
                    styles["Heading2"]
                )
            )

            for item in values:
                content.append(
                    Paragraph(
                        f"• {item}",
                        styles["BodyText"]
                    )
                )

    content.append(Spacer(1, 12))

    # MITRE

    content.append(
        Paragraph(
            "MITRE ATT&CK Mapping",
            styles["Heading1"]
        )
    )

    mitre = payload.get("mitre", [])

    if mitre:
        for item in mitre:
            content.append(
                Paragraph(
                    f"• {item}",
                    styles["BodyText"]
                )
            )
    else:
        content.append(
            Paragraph(
                "No MITRE techniques mapped.",
                styles["BodyText"]
            )
        )

    content.append(Spacer(1, 12))

    # VirusTotal

    content.append(
        Paragraph(
            "VirusTotal Intelligence",
            styles["Heading1"]
        )
    )

    vt = payload.get("vt_result")

    if vt:

        content.append(
            Paragraph(
                f"Malicious: {vt.get('malicious',0)}",
                styles["BodyText"]
            )
        )

        content.append(
            Paragraph(
                f"Suspicious: {vt.get('suspicious',0)}",
                styles["BodyText"]
            )
        )

        content.append(
            Paragraph(
                f"Harmless: {vt.get('harmless',0)}",
                styles["BodyText"]
            )
        )

        content.append(
            Paragraph(
                f"Undetected: {vt.get('undetected',0)}",
                styles["BodyText"]
            )
        )

    else:

        content.append(
            Paragraph(
                "VirusTotal data unavailable.",
                styles["BodyText"]
            )
        )

    content.append(Spacer(1, 12))

    # Recommendations

    content.append(
        Paragraph(
            "SOC Analyst Recommendation",
            styles["Heading1"]
        )
    )

    score = payload["overall_score"]

    if score < 20:

        recommendation = (
            "Communication appears benign. "
            "No containment action required."
        )

    elif score < 40:

        recommendation = (
            "Minor anomalies detected. "
            "User awareness recommended."
        )

    elif score < 70:

        recommendation = (
            "Suspicious communication detected. "
            "Manual investigation advised."
        )

    else:

        recommendation = (
            "High confidence phishing attempt detected. "
            "Immediate containment required."
        )

    content.append(
        Paragraph(
            recommendation,
            styles["BodyText"]
        )
    )

    pdf.build(content)

    return filename