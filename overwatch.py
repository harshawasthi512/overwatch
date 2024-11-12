import json
import requests
import dns.resolver
import argparse
import sys

def load_service_signatures(file_path='service_signatures.json'):
    """Load service error signatures from a JSON file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            return json.load(file)
    except Exception as e:
        print(f"[!] Error loading service signatures: {e}")
        sys.exit(1)


def load_subdomains(file_path):
    """Load subdomains from a text file."""
    try:
        with open(file_path, 'r') as file:
            return [line.strip() for line in file if line.strip()]
    except Exception as e:
        print(f"[!] Error loading subdomains: {e}")
        sys.exit(1)

def check_subdomain_takeover(subdomain, service_signatures):
    """Check if the subdomain is vulnerable to takeover based on known service signatures."""
    try:
        # Get the DNS CNAME record for the subdomain
        answers = dns.resolver.resolve(subdomain, 'CNAME')
        cname_target = answers[0].target.to_text()
        
        # Check if the CNAME matches any known vulnerable service
        for service, error_message in service_signatures.items():
            if service in cname_target:
                # Check HTTP response to confirm vulnerability
                response = requests.get(f"http://{subdomain}")
                if error_message in response.text:
                    return "Vulnerable", f"{subdomain} -> {cname_target} (Error: {error_message})"
                else:
                    return "Not Vulnerable", f"{subdomain} -> {cname_target} (CNAME points to {service})"
                
        return "Not Vulnerable", f"{subdomain} -> No takeover risk found"
    
    except dns.resolver.NoAnswer:
        return "Not Vulnerable", f"{subdomain} -> No CNAME record found"
    except (requests.ConnectionError, dns.resolver.NXDOMAIN):
        return "Not Vulnerable", f"{subdomain} -> Subdomain unreachable or does not exist"
    except Exception as e:
        return "Error", f"{subdomain} -> Error: {e}"
    
CYAN = "\033[36m"
RED = "\33[91m"
BLUE = "\33[94m"
GREEN = "\033[32m"
YELLOW = "\033[93m"
PURPLE = '\033[0;35m'

def create_banner():  
    """Creates the banner of the project"""
    print(
    f"""{CYAN}{"-"*82}

░█████╗░██╗░░░██╗███████╗██████╗░░██╗░░░░░░░██╗░█████╗░████████╗░█████╗░██╗░░██╗
██╔══██╗██║░░░██║██╔════╝██╔══██╗░██║░░██╗░░██║██╔══██╗╚══██╔══╝██╔══██╗██║░░██║
██║░░██║╚██╗░██╔╝█████╗░░██████╔╝░╚██╗████╗██╔╝███████║░░░██║░░░██║░░╚═╝███████║
██║░░██║░╚████╔╝░██╔══╝░░██╔══██╗░░████╔═████║░██╔══██║░░░██║░░░██║░░██╗██╔══██║
╚█████╔╝░░╚██╔╝░░███████╗██║░░██║░░╚██╔╝░╚██╔╝░██║░░██║░░░██║░░░╚█████╔╝██║░░██║
░╚════╝░░░░╚═╝░░░╚══════╝╚═╝░░╚═╝░░░╚═╝░░░╚═╝░░╚═╝░░╚═╝░░░╚═╝░░░░╚════╝░╚═╝░░╚═╝ 1.0"""
)
    print(f"\nSubdomain Takeover Vulnerability Scanner")
    print(f"Developed in Python by - {GREEN}Harsh Awasthi") 
    
    
def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description="Subdomain Takeover Scanner")
    parser.add_argument("-t", "--targets", required=True, help="Path to the file containing subdomains to check")
    parser.add_argument("-s", "--signatures", default="service_signatures.json", help="Path to the service signatures JSON file")
    
    # Parse arguments
    args = parser.parse_args()
    
    # Load service signatures and subdomains
    service_signatures = load_service_signatures(args.signatures)
    subdomains = load_subdomains(args.targets)
    

    create_banner()
    print("\nSubdomain Takeover Scan Results:\n")
    for subdomain in subdomains:
        status, message = check_subdomain_takeover(subdomain, service_signatures)
        color = RED if status == "Vulnerable" else GREEN
        print(f"{color}{subdomain}: [{status}] - {message}")
       

if __name__ == "__main__":
    main()
