import re

def analyze_email(email_text):
    risk_score = 0
    warnings = []

    # Suspicious keywords
    urgent_words = [
        "urgent", "immediately", "verify your account",
        "click here", "act now", "limited time"
    ]

    # Check for urgent requests
    for word in urgent_words:
        if word.lower() in email_text.lower():
            risk_score += 1
            warnings.append(f"Suspicious phrase detected: '{word}'")

    # Check for links
    links = re.findall(r'https?://\S+|www\.\S+', email_text)
    if links:
        risk_score += len(links)
        warnings.append(f"Found {len(links)} link(s) in the email.")

    # Check for sensitive data requests
    sensitive_terms = [
        "password", "bank account", "credit card",
        "otp", "ssn", "pin"
    ]

    for term in sensitive_terms:
        if term.lower() in email_text.lower():
            risk_score += 2
            warnings.append(f"Sensitive information request detected: '{term}'")

    # Risk Classification
    if risk_score >= 5:
        risk_level = "HIGH RISK"
    elif risk_score >= 3:
        risk_level = "MEDIUM RISK"
    else:
        risk_level = "LOW RISK"

    print("\n--- Email Analysis Report ---")
    print("Risk Level:", risk_level)

    if warnings:
        print("\nWarnings:")
        for warning in warnings:
            print("-", warning)
    else:
        print("No suspicious content detected.")

# User Input
email_content = input("Paste the email content:\n")

analyze_email(email_content)