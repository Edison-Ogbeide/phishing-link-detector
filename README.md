# Phishing Link Detector

A Python-based tool that scans URLs for suspicious patterns and integrates with the VirusTotal API to identify potential phishing threats.

## Features

- Detects common phishing indicators in URLs:
  - URL shorteners (bit.ly, tinyurl.com, etc.)
  - IP addresses instead of domain names
  - Suspicious keywords (login, verify, secure, etc.)
  - Brand impersonation attempts
  - Unusually long subdomains
  - Multiple TLDs
- Checks domain registration age (new domains are higher risk)
- Integrates with VirusTotal API for comprehensive threat intelligence
- Calculates risk score based on multiple factors
- Provides detailed analysis output in both human-readable and JSON formats

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/phishing-link-detector.git
   cd phishing-link-detector
   ```

2. Install required dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Get a VirusTotal API key:
   - Sign up at [VirusTotal](https://www.virustotal.com/)
   - Go to your profile to find your API key
   - (Free API keys have limited daily requests)

## Usage

### Basic URL Check

```bash
python phishing_detector.py "https://example.com"
```

### Using VirusTotal API

```bash
python phishing_detector.py "https://example.com" --api-key YOUR_VIRUSTOTAL_API_KEY
```

Or set it as an environment variable:

```bash
export VIRUSTOTAL_API_KEY=your_api_key_here
python phishing_detector.py "https://example.com"
```

### Output Options

Output results to a file:
```bash
python phishing_detector.py "https://example.com" --output results.json
```

Get results in JSON format:
```bash
python phishing_detector.py "https://example.com" --json
```

## How It Works

The Phishing Link Detector uses a multi-layered approach to identify potential threats:

1. **Pattern Matching**: Checks the URL against common patterns used in phishing attacks
2. **Domain Analysis**: Verifies if the domain is newly registered (often a red flag)
3. **Threat Intelligence**: Leverages VirusTotal's database of known threats
4. **Risk Scoring**: Calculates an overall risk score based on all collected data

## Risk Score Calculation

The risk score (0-100) is calculated based on:
- Number of suspicious patterns detected
- Whether the domain is newly registered
- VirusTotal detection results

Risk levels:
- 0-19: Minimal Risk
- 20-49: Low Risk
- 50-79: Medium Risk
- 80-100: High Risk

## Example Output

```
===== Phishing Analysis Results for https://example.com =====
Timestamp: 2025-04-03 15:30:45
Risk Score: 20/100 (Low Risk)

Suspicious Patterns Detected:
- login|signin|verify|account

Domain Age: Established domain

VirusTotal Results:
- Malicious: 0
- Suspicious: 1
- Harmless: 67
- Undetected: 3

Recommendation: Probably safe, but verify before clicking.
```

## Contributing

Contributions are welcome! Feel free to submit pull requests for new features, improvements, or bug fixes.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is provided for educational and defensive purposes only. The author is not responsible for any misuse of this software. Always verify URLs through multiple sources before interacting with them.
