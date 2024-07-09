import argparse
import whois
import dns.resolver
import ssl
import socket
import requests
from urllib.parse import urlparse
from datetime import datetime
import geoip2.database
import signal
import sys

# ANSI color codes for green text
GREEN = '\033[92m'
RESET = '\033[0m'
BLUE = '\33[94m'

ascii_art = """
▒█▀▀▄ █▀▀█ █▀▄▀█ █▀▀█ ░▀░ █▀▀▄ ▀█▀ █▀▀▄ █▀▀ █▀▀█ █▀▀ █▀▀ ▀▀█▀▀ █▀▀█ █▀▀█ 
▒█░▒█ █░░█ █░▀░█ █▄▄█ ▀█▀ █░░█ ▒█░ █░░█ ▀▀█ █░░█ █▀▀ █░░ ░░█░░ █░░█ █▄▄▀ 
▒█▄▄▀ ▀▀▀▀ ▀░░░▀ ▀░░▀ ▀▀▀ ▀░░▀ ▄█▄ ▀░░▀ ▀▀▀ █▀▀▀ ▀▀▀ ▀▀▀ ░░▀░░ ▀▀▀▀ ▀░▀▀
"""

developer_name = "D E V E L O P E D  B Y  K U N A L  N A M D A S"

# Function to display ASCII art
def display_ascii_art(ascii_art):
    print(GREEN + ascii_art + RESET)
    total_width = len(ascii_art.split('\n')[1])
    spaces = " " * ((total_width - len(developer_name)) // 2)
    print(spaces + developer_name + RESET)

# Function to handle Ctrl+C gracefully
def signal_handler(sig, frame):
    print("\n" + GREEN + "[+] Exiting gracefully..." + RESET)
    sys.exit(0)

# Install signal handler for Ctrl+C
signal.signal(signal.SIGINT, signal_handler)

# Function to extract domain from URL or validate IP address
def extract_domain_or_ip(url_or_ip):
    parsed_url = urlparse(url_or_ip)
    if parsed_url.netloc:
        return parsed_url.netloc
    else:
        return url_or_ip

# Function to perform geolocation using IP address
def geolocate_ip(ip):
    try:
        reader = geoip2.database.Reader('GeoLite2-City.mmdb')
        response = reader.city(ip)
        return f"{response.city.name}, {response.subdivisions.most_specific.name}, {response.country.name}"
    except Exception as e:
        return str(e)

# Function to perform reverse DNS lookup
def reverse_dns_lookup(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception as e:
        return str(e)

# Function to check HTTP/HTTPS status and retrieve headers
def check_http_status(url):
    try:
        response = requests.get(url, timeout=10)
        return response.status_code, response.reason, response.headers
    except requests.exceptions.RequestException as e:
        return f"Error: {str(e)}", None, None

# Function to retrieve SSL certificate details
def get_ssl_certificate_details(domain_or_ip):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain_or_ip, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain_or_ip) as ssock:
                cert = ssock.getpeercert()

                # Extract relevant fields from the certificate
                issuer = dict(x[0] for x in cert['issuer'])
                subject = dict(x[0] for x in cert['subject'])
                not_before = datetime.strptime(cert['notBefore'], "%b %d %H:%M:%S %Y %Z")
                not_after = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")

                return {
                    "issuer": issuer.get('organizationName', ''),
                    "subject": subject.get('organizationName', ''),
                    "valid_from": not_before,
                    "valid_to": not_after,
                    "version": cert['version'],
                    "serial_number": cert['serialNumber'],
                    "signature_algorithm": cert['signatureAlgorithm'],
                    "public_key": cert['subjectPublicKeyInfo']['subjectPublicKey']
                }

    except ssl.SSLError as e:
        return f"SSL Error: {e}"
    except ConnectionRefusedError:
        return "Connection Refused"
    except ConnectionError as e:
        return f"Connection Error: {e}"
    except Exception as e:
        return f"SSL certificate error: {e}"

# Function to perform subdomain enumeration using crt.sh API
def enumerate_subdomains(domain):
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(url)
        if response.status_code == 200:
            subdomains = set()
            for entry in response.json():
                subdomains.add(entry['name_value'].strip())
            return list(subdomains)
        else:
            return []
    except Exception as e:
        return []

# Main function to gather domain information
def domain_info_tool(url_or_ip):
    domain_or_ip = extract_domain_or_ip(url_or_ip)
    try:
        print(GREEN + f"\n[+] Domain or IP: {domain_or_ip}" + RESET)

        if '.' in domain_or_ip:  # Perform domain-related operations
            # Perform a WHOIS lookup
            try:
                whois_info = whois.whois(domain_or_ip)

                # Print out relevant information with [+] symbol
                print(GREEN + f"[+] Registrar: {whois_info.registrar}" + RESET)
                print(GREEN + f"[+] Creation Date: {whois_info.creation_date}" + RESET)
                print(GREEN + f"[+] Expiration Date: {whois_info.expiration_date}" + RESET)
                print(GREEN + f"[+] Name Servers: {', '.join(whois_info.name_servers)}" + RESET)
                print(GREEN + f"[+] Updated Date: {whois_info.updated_date}" + RESET)
                print(GREEN + f"[+] Status: {', '.join(whois_info.status)}" + RESET)

                # Print Registrant information if available
                if whois_info.name:
                    print(GREEN + f"[+] Registrant Name: {whois_info.name}" + RESET)
                if whois_info.org:
                    print(GREEN + f"[+] Registrant Organization: {whois_info.org}" + RESET)
                if whois_info.address:
                    print(GREEN + f"[+] Registrant Address: {whois_info.address}" + RESET)
                if whois_info.emails:
                    print(GREEN + f"[+] Registrant Email: {', '.join(whois_info.emails)}" + RESET)
                if whois_info.phone:
                    print(GREEN + f"[+] Registrant Phone: {whois_info.phone}" + RESET)

            except Exception as e:
                print(f"Error: {e}")

            # Perform DNS resolution for additional records
            print(GREEN + "\n[+] Performing DNS resolution:" + RESET)
            try:
                # Resolve A records (IPv4 addresses)
                a_records = dns.resolver.resolve(domain_or_ip, 'A')
                print(GREEN + "[+] A Records (IPv4 addresses):" + RESET)
                for record in a_records:
                    print(GREEN + f"    {record}" + RESET)

                # Resolve MX records (Mail servers)
                mx_records = dns.resolver.resolve(domain_or_ip, 'MX')
                print(GREEN + "\n[+] MX Records (Mail servers):" + RESET)
                for record in mx_records:
                    print(GREEN + f"    {record.exchange} (Priority: {record.preference})" + RESET)

                # Resolve TXT records (SPF, DKIM, etc.)
                txt_records = dns.resolver.resolve(domain_or_ip, 'TXT')
                print(GREEN + "\n[+] TXT Records (Text records):" + RESET)
                for record in txt_records:
                    print(GREEN + f"    {record.to_text()}" + RESET)

                # Check DNSSEC status
                try:
                    answer = dns.resolver.resolve(domain_or_ip, 'DNSKEY', raise_on_no_answer=False)
                    dnssec_enabled = bool(answer.response.flags & dns.flags.DO)
                    print(GREEN + f"[+] DNSSEC: {'Enabled' if dnssec_enabled else 'Disabled'}" + RESET)
                except Exception as e:
                    print(GREEN + f"[+] DNSSEC check failed: {e}" + RESET)

            except dns.resolver.NoAnswer:
                print(GREEN + "[+] No DNS records found." + RESET)
            except dns.resolver.NXDOMAIN:
                print(GREEN + "[+] The domain does not exist." + RESET)
            except dns.resolver.Timeout:
                print(GREEN + "[+] DNS resolution timed out." + RESET)
            except Exception as e:
                print(GREEN + f"[+] DNS resolution error: {e}" + RESET)

            # SSL Certificate Information
            print(GREEN + "\n[+] SSL Certificate Information:" + RESET)
            try:
                ssl_details = get_ssl_certificate_details(domain_or_ip)
                if isinstance(ssl_details, dict):
                    print(GREEN + f"    Issuer: {ssl_details['issuer']}" + RESET)
                    print(GREEN + f"    Subject: {ssl_details['subject']}" + RESET)
                    print(GREEN + f"    Valid From: {ssl_details['valid_from']}" + RESET)
                    print(GREEN + f"    Valid To: {ssl_details['valid_to']}" + RESET)
                    print(GREEN + f"    Version: {ssl_details['version']}" + RESET)
                    print(GREEN + f"    Serial Number: {ssl_details['serial_number']}" + RESET)
                    print(GREEN + f"    Signature Algorithm: {ssl_details['signature_algorithm']}" + RESET)
                    # For security reasons, public key is omitted in output
                    # print(GREEN + f"    Public Key: {ssl_details['public_key']}" + RESET)
                else:
                    print(GREEN + f"    {ssl_details}" + RESET)

            except Exception as e:
                print(GREEN + f"[+] SSL certificate error: {e}" + RESET)

            # Additional Network Information
            print(GREEN + "\n[+] Additional Network Information:" + RESET)
            try:
                # Perform geolocation using IP address
                ip_addresses = [str(record) for record in a_records]
                print(GREEN + "[+] Geolocation (using IP):" + RESET)
                for ip in ip_addresses:
                    location = geolocate_ip(ip)
                    print(GREEN + f"    IP: {ip} -> Location: {location}" + RESET)

                # Perform reverse DNS lookup
                print(GREEN + "\n[+] Reverse DNS Lookup:" + RESET)
                for ip in ip_addresses:
                    rdns = reverse_dns_lookup(ip)
                    print(GREEN + f"    IP: {ip} -> Hostname: {rdns}" + RESET)

                # Check HTTP/HTTPS status and retrieve headers
                print(GREEN + "\n[+] HTTP/HTTPS Status and Headers:" + RESET)
                url = f"http://{domain_or_ip}" if "http://" not in domain_or_ip else domain_or_ip
                status_code, status_reason, headers = check_http_status(url)
                print(GREEN + f"    URL: {url} -> Status Code: {status_code} ({status_reason})" + RESET)
                if headers:
                    print(GREEN + "[+] Headers:" + RESET)
                    for header, value in headers.items():
                        print(GREEN + f"        {header}: {value}" + RESET)

                url_https = f"https://{domain_or_ip}" if "https://" not in domain_or_ip else domain_or_ip
                status_code_https, status_reason_https, headers_https = check_http_status(url_https)
                print(GREEN + f"    URL: {url_https} -> Status Code: {status_code_https} ({status_reason_https})" + RESET)
                if headers_https:
                    print(GREEN + "[+] Headers:" + RESET)
                    for header, value in headers_https.items():
                        print(GREEN + f"        {header}: {value}" + RESET)

                # Perform subdomain enumeration using crt.sh API
                print(GREEN + "\n[+] Subdomain Enumeration:" + RESET)
                subdomains = enumerate_subdomains(domain_or_ip)
                if subdomains:
                    print(GREEN + f"    Found {len(subdomains)} subdomains:" + RESET)
                    for subdomain in subdomains:
                        print(GREEN + f"        {subdomain}" + RESET)
                else:
                    print(GREEN + "    No subdomains found." + RESET)

            except Exception as e:
                print(GREEN + f"[+] Error fetching additional network information: {e}" + RESET)

        else:  # Perform IP-related operations
            # Perform WHOIS lookup for IP address
            print(GREEN + "\n[+] Performing WHOIS lookup for IP address:" + RESET)
            try:
                whois_info = whois.whois(domain_or_ip)
                print(GREEN + f"[+] IP: {domain_or_ip}" + RESET)
                print(GREEN + f"[+] WHOIS information:" + RESET)
                print(GREEN + f"    {whois_info}" + RESET)
            except Exception as e:
                print(f"Error: {e}")

            # Additional IP-related information
            print(GREEN + "\n[+] Additional IP Information:" + RESET)
            try:
                # Perform geolocation using IP address
                print(GREEN + "[+] Geolocation (using IP):" + RESET)
                location = geolocate_ip(domain_or_ip)
                print(GREEN + f"    IP: {domain_or_ip} -> Location: {location}" + RESET)

                # Perform reverse DNS lookup
                print(GREEN + "\n[+] Reverse DNS Lookup:" + RESET)
                rdns = reverse_dns_lookup(domain_or_ip)
                print(GREEN + f"    IP: {domain_or_ip} -> Hostname: {rdns}" + RESET)

            except Exception as e:
                print(GREEN + f"[+] Error fetching additional IP information: {e}" + RESET)

    except Exception as e:
        print(f"Error: {e}")

# Main execution
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Domain and IP information tool')
    parser.add_argument('url_or_ip', metavar='URL_or_IP', type=str, help='URL or IP address to lookup')
    args = parser.parse_args()

    # Display ASCII art and developer name
    display_ascii_art(ascii_art)

    # Execute the main tool
    domain_info_tool(args.url_or_ip)
