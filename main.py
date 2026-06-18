import logging
from urllib.parse import urljoin

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

class WebScanner:
    def __init__(self, target_url):
        self.target = target_url
        self.findings = []
        
    def check_headers(self):
        logging.info(f"Scanning headers for {self.target}")
        # Mock checking headers
        missing_headers = ['Strict-Transport-Security', 'X-Frame-Options']
        for h in missing_headers:
            self.findings.append({"type": "Missing Header", "detail": h, "severity": "Medium"})
            
    def check_endpoints(self):
        logging.info("Scanning common endpoints...")
        endpoints = ['/admin', '/.git/config', '/.env']
        for ep in endpoints:
            # Mock finding an exposed endpoint
            if ep == '/.env':
                self.findings.append({"type": "Exposed File", "detail": ep, "severity": "High"})

    def report(self):
        print("\n=== Scan Report for {} ===".format(self.target))
        if not self.findings:
            print("No vulnerabilities found.")
        else:
            for f in self.findings:
                print(f"[{f['severity']}] {f['type']}: {f['detail']}")
        print("===========================\n")

if __name__ == "__main__":
    scanner = WebScanner("https://example.com")
    scanner.check_headers()
    scanner.check_endpoints()
    scanner.report()