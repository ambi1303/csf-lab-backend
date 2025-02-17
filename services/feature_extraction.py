import pandas as pd

def extract_features(scan_report):
    features = []
    for alert in scan_report.get("alerts", []):
        features.append({
            "request_method": alert.get("method", "GET"),
            "url_pattern": alert.get("url", "").split("?")[0],
            "alert_type": alert.get("name", "Unknown"),
            "response_headers": alert.get("responseHeaders", ""),
            "response_body": alert.get("responseBody", ""),
            "cvss_score": float(alert.get("cvssScore", 0)),
            "severity": alert.get("risk", "Low"),
            "reference_urls": ", ".join(alert.get("reference", []))
        })
    
    return pd.DataFrame(features)
