import re
import requests
import argparse
import json
import os
from urllib.parse import urlparse
from datetime import datetime

class PhishingDetector:
    def __init__(self, api_key=None):
        self.api_key = api_key or os.getenv('VIRUSTOTAL_API_KEY')
        if not self.api_key:
            print("Warning: No VirusTotal API key provided. Limited functionality available.")
        
        # Suspicious patterns in URLs
        self.suspicious_patterns = [
            r'bit\.ly', r'tinyurl\.com', r'goo\.gl',  # URL shorteners
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',    # IP addresses
            r'(secure|login|signin|verify|account|banking|update|confirm)',  # Phishing keywords
            r'(paypal|apple|microsoft|google|amazon|facebook|instagram).*\.(com|net|org|info)$',  # Brand impersonation
            r'[a-zA-Z0-9]{25,}',      # Unusually long subdomains
            r'[a-zA-Z0-9]+\.[a-z]{2,3}\.[a-z]{2,3}',  # Multiple TLDs
        ]
    
    def check_patterns(self, url):
        """Check URL for suspicious patterns"""
        matches = []
        for pattern in self.suspicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                matches.append(pattern)
        return matches
    
    def check_domain_age(self, url):
        """Check if domain is newly registered (if whois module is available)"""
        try:
            import whois
            domain = urlparse(url).netloc
            w = whois.whois(domain)
            
            if w.creation_date:
                # Handle both single date and list of dates
                creation_date = w.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                
                domain_age_days = (datetime.now() - creation_date).days
                if domain_age_days < 30:
                    return True, domain_age_days
            return False, None
        except:
            return None, None  # Couldn't determine
    
    def scan_url_virustotal(self, url):
        """Scan URL using VirusTotal API"""
        if not self.api_key:
            return None
        
        try:
            headers = {
                "x-apikey": self.api_key,
                "Accept": "application/json"
            }
            
            # First get the URL ID
            url_id = requests.post(
                "https://www.virustotal.com/api/v3/urls", 
                data={"url": url},
                headers=headers
            )
            
            if url_id.status_code != 200:
                return {"error": "Failed to submit URL", "code": url_id.status_code}
            
            analysis_id = url_id.json().get("data", {}).get("id")
            if not analysis_id:
                return {"error": "No analysis ID returned"}
            
            # Get the analysis
            response = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers
            )
            
            if response.status_code != 200:
                return {"error": "Failed to get analysis", "code": response.status_code}
            
            return response.json()
        except Exception as e:
            return {"error": str(e)}
    
    def analyze_url(self, url):
        """Complete URL analysis"""
        results = {
            "url": url,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "suspicious_patterns": self.check_patterns(url),
            "parsed_url": {
                "scheme": urlparse(url).scheme,
                "netloc": urlparse(url).netloc,
                "path": urlparse(url).path,
                "params": urlparse(url).params,
                "query": urlparse(url).query,
                "fragment": urlparse(url).fragment
            }
        }
        
        # Check domain age
        is_new_domain, domain_age = self.check_domain_age(url)
        if is_new_domain is not None:
            results["new_domain"] = is_new_domain
            results["domain_age_days"] = domain_age
        
        # Check with VirusTotal if API key is available
        if self.api_key:
            vt_results = self.scan_url_virustotal(url)
            if vt_results and not vt_results.get("error"):
                # Extract relevant information from VirusTotal results
                vt_data = vt_results.get("data", {}).get("attributes", {})
                stats = vt_data.get("stats", {})
                
                results["virustotal"] = {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0)
                }
        
        # Calculate risk score (simple algorithm)
        risk_score = len(results["suspicious_patterns"]) * 20
        
        if results.get("new_domain"):
            risk_score += 30
        
        if results.get("virustotal"):
            vt = results["virustotal"]
            if vt["malicious"] > 0:
                risk_score += min(vt["malicious"] * 10, 50)
            if vt["suspicious"] > 0:
                risk_score += min(vt["suspicious"] * 5, 20)
        
        # Cap at 100
        results["risk_score"] = min(risk_score, 100)
        results["risk_level"] = self._get_risk_level(results["risk_score"])
        
        return results
    
    def _get_risk_level(self, score):
        if score >= 80:
            return "High"
        elif score >= 50:
            return "Medium"
        elif score >= 20:
            return "Low"
        else:
            return "Minimal"

def main():
    parser = argparse.ArgumentParser(description="Phishing URL Detector")
    parser.add_argument("url", help="URL to check")
    parser.add_argument("--api-key", help="VirusTotal API key")
    parser.add_argument("--output", help="Output results to file")
    parser.add_argument("--json", action="store_true", help="Output in JSON format")
    args = parser.parse_args()
    
    detector = PhishingDetector(api_key=args.api_key)
    results = detector.analyze_url(args.url)
    
    if args.json:
        output = json.dumps(results, indent=4)
        print(output)
    else:
        print(f"\n===== Phishing Analysis Results for {args.url} =====")
        print(f"Timestamp: {results['timestamp']}")
        print(f"Risk Score: {results['risk_score']}/100 ({results['risk_level']} Risk)")
        
        print("\nSuspicious Patterns Detected:")
        if results["suspicious_patterns"]:
            for pattern in results["suspicious_patterns"]:
                print(f"- {pattern}")
        else:
            print("- None detected")
        
        if "new_domain" in results:
            print(f"\nDomain Age: {'New domain! Only ' + str(results['domain_age_days']) + ' days old' if results['new_domain'] else 'Established domain'}")
        
        if "virustotal" in results:
            vt = results["virustotal"]
            print("\nVirusTotal Results:")
            print(f"- Malicious: {vt['malicious']}")
            print(f"- Suspicious: {vt['suspicious']}")
            print(f"- Harmless: {vt['harmless']}")
            print(f"- Undetected: {vt['undetected']}")
        
        print(f"\nRecommendation: {'Treat with extreme caution!' if results['risk_level'] in ['Medium', 'High'] else 'Probably safe, but verify before clicking.'}")
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=4)
        print(f"\nResults saved to {args.output}")

if __name__ == "__main__":
    main()
