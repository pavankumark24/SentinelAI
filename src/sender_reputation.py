import re


def analyze_sender(text):

    findings = []
    score = 0

    brands = [
        "google",
        "amazon",
        "microsoft",
        "paypal",
        "apple",
        "facebook",
        "instagram",
        "netflix",
        "linkedin",
        "github"
    ]

    # Improvement 2: Added common typosquatting lookalike keywords
    lookalikes = [
        "googlee",
        "g00gle",
        "goog1e",
        "amaz0n",
        "micr0soft",
        "paypa1"
    ]

    text_lower = text.lower()

    email_pattern = r'[\w\.-]+@[\w\.-]+'

    emails = re.findall(
        email_pattern,
        text_lower
    )

    for email in emails:

        domain = email.split("@")[1]

        findings.append(
            f"📧 Sender: {email}"
        )

        if domain.endswith(
            (
                ".xyz",
                ".top",
                ".click",
                ".gq",
                ".tk"
            )
        ):

            score += 25

            findings.append(
                "⚠️ Suspicious Sender Domain"
            )

        # Improvement 2: Check for Typosquatting/Lookalike domains
        if any(fake in domain for fake in lookalikes):

            score += 50

            findings.append(
                "🚨 Typosquatting Domain"
            )

        for brand in brands:

            if brand in domain:
                # Improvement 1: Expanded to check a list of trusted domains instead of a single string
                trusted_domains = [
                    f"{brand}.com",
                    f"mail.{brand}.com",
                    f"support.{brand}.com"
                ]

                if domain not in trusted_domains:

                    score += 40

                    findings.append(
                        f"⚠️ Possible {brand.title()} Impersonation"
                    )

    # Improvement 3: Severity classification matching the criteria provided
    if score < 20:
        severity = "LOW"

    elif score < 50:
        severity = "MEDIUM"

    else:
        severity = "HIGH"

    # Improvement 3: Returning the calculated severity classification alongside score and findings
    return {
        "score": score,
        "severity": severity,
        "findings": findings
    }