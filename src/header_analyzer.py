import email
import dns.resolver

def parse_and_audit_headers(raw_email_string):
    """
    Parses raw email headers to extract key threat intelligence metadata 
    and audits the sender domain's live DMARC/SPF security posture.
    """
    results = {
        "from": "Unknown",
        "return_path": "Unknown",
        "spf_policy": "None Found",
        "dmarc_policy": "None Found",
        "spoof_risk": 0,
        "findings": []
    }
    
    if not raw_email_string.strip():
        return results

    try:
        # Parse the raw email string structural data
        msg = email.message_from_string(raw_email_string)
        
        results["from"] = msg.get("From", "Unknown")
        results["return_path"] = msg.get("Return-Path", "Unknown")
        
        # Clean and isolate the sender domain string
        from_header = results["from"]
        if "@" in from_header:
            # Extracts 'paypal.com' from 'PayPal Support <security@paypal.com>'
            domain = from_header.split("@")[-1].replace(">", "").replace("<", "").strip()
        else:
            domain = from_header.strip()

        if not domain or "." not in domain:
            return results

        # --- AUDIT SPF RECORD ---
        try:
            txt_records = dns.resolver.resolve(domain, 'TXT', search=False)
            spf_found = False
            for record in txt_records:
                record_text = record.to_text()
                if "v=spf1" in record_text:
                    results["spf_policy"] = record_text
                    spf_found = True
                    if "-all" in record_text:
                        results["findings"].append(f"✅ Strict SPF policy enforced (-all) by {domain}.")
                    elif "~all" in record_text:
                        results["findings"].append(f"⚠️ SoftFail SPF configuration (~all) detected for {domain}.")
                        results["spoof_risk"] += 15
                    elif "?all" in record_text:
                        results["findings"].append(f"🚨 Neutral SPF configuration (?all) detected. Domain allows soft validation spoofing.")
                        results["spoof_risk"] += 30
            
            if not spf_found:
                results["findings"].append(f"🚨 Missing SPF configuration syntax within existing TXT records for {domain}.")
                results["spoof_risk"] += 40
                
        except Exception:
            results["findings"].append(f"🚨 MISSING SPF RECORD: {domain} has no SPF policy configuration published in DNS.")
            results["spoof_risk"] += 45

        # --- AUDIT DMARC RECORD ---
        try:
            dmarc_records = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT', search=False)
            dmarc_found = False
            for record in dmarc_records:
                record_text = record.to_text()
                if "v=DMARC1" in record_text:
                    results["dmarc_policy"] = record_text
                    dmarc_found = True
                    if "p=reject" in record_text:
                        results["findings"].append(f"✅ Strong DMARC Policy: Unauthorized spoofing vectors are completely rejected (p=reject).")
                    elif "p=quarantine" in record_text:
                        results["findings"].append(f"⚠️ Moderate DMARC Policy: Unauthorized emails are sent directly to spam (p=quarantine).")
                        results["spoof_risk"] += 10
                    elif "p=none" in record_text:
                        results["findings"].append(f"🚨 WEAK DMARC POLICY: Domain explicitly uses 'p=none' (Monitoring only). Domain is highly vulnerable to spoofing.")
                        results["spoof_risk"] += 40
            
            if not dmarc_found:
                results["findings"].append(f"🚨 Missing DMARC core structural format flag on lookups.")
                results["spoof_risk"] += 45
                
        except Exception:
            results["findings"].append(f"🚨 MISSING DMARC RECORD: {domain} does not protect its brand against domain spoofing.")
            results["spoof_risk"] += 55

        # Cap maximum risk score output at 100
        results["spoof_risk"] = min(results["spoof_risk"], 100)
        return results

    except Exception as e:
        print(f"[!] Critical error inside header_analyzer module: {e}")
        return results