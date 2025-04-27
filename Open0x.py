from colorama import Fore, Style, init
import requests
import argparse
import re
from pathlib import Path
from urllib.parse import quote, urlparse

init(autoreset=True)


def print_banner():
    banner = f"""

{Fore.RED}░█████╗{Fore.BLUE}░██████╗░███████╗███╗░░██╗{Fore.GREEN}░█████╗{Fore.YELLOW}░██╗░░██╗
{Fore.RED}██╔══██╗{Fore.BLUE}██╔══██╗██╔════╝████╗░██║{Fore.GREEN}██╔══██╗{Fore.YELLOW}╚██╗██╔╝
{Fore.RED}██║░░██║{Fore.BLUE}██████╔╝█████╗░░██╔██╗██║{Fore.GREEN}██║░░██║{Fore.YELLOW}░╚███╔╝░
{Fore.RED}██║░░██║{Fore.BLUE}██╔═══╝░██╔══╝░░██║╚████║{Fore.GREEN}██║░░██║{Fore.YELLOW}░██╔██╗░
{Fore.RED}╚█████╔╝{Fore.BLUE}██║░░░░░███████╗██║░╚███║{Fore.GREEN}╚█████╔╝{Fore.YELLOW}██╔╝╚██╗
{Fore.RED}░╚════╝░{Fore.BLUE}╚═╝░░░░░╚══════╝╚═╝░░╚══╝{Fore.GREEN}░╚════╝░{Fore.YELLOW}╚═╝░░╚═╝                       

    """
    print(banner + Style.RESET_ALL)


print_banner()


def clean_domain(domain):
    """Remove protocols and unnecessary parts from domain"""
    parsed = urlparse(domain)
    cleaned = parsed.netloc or parsed.path
    cleaned = re.sub(r'^www\.', '', cleaned).strip().lower()
    return cleaned if '.' in cleaned else None


def fetch_archived_urls(domain):
    base_url = "https://web.archive.org/cdx/search/cdx"
    params = {
        'url': f'{quote(domain)}/*',
        'matchType': 'prefix',
        'collapse': 'urlkey',
        'output': 'text',
        'fl': 'original'
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
    }

    try:
        response = requests.get(base_url, params=params, headers=headers, timeout=10)
        response.raise_for_status()
        return [url.strip() for url in response.text.splitlines() if url.strip()]
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[-] Wayback Error: {e}")
        return []


def fetch_otx_urls(domain):
    base_url = f"https://otx.alienvault.com/api/v1/indicators/hostname/{domain}/url_list"
    params = {
        'limit': 500,
        'page': 1
    }
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
    }

    try:
        response = requests.get(base_url, params=params, headers=headers, timeout=10)
        response.raise_for_status()
        return [item['url'] for item in response.json().get('url_list', [])]
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[-] OTX Error: {e}")
        return []


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Collect and filter archived URLs")
    parser.add_argument('-d', '--domain', required=True, help="Target domain (e.g. example.com)")
    parser.add_argument('-o', '--output', help="Output file for normal URLs")
    args = parser.parse_args()

    # Clean and validate domain
    cleaned_domain = clean_domain(args.domain)
    if not cleaned_domain:
        print(f"{Fore.RED}[-] Invalid domain format")
        exit(1)

    print(f"{Fore.CYAN}[+] Processing domain: {Fore.YELLOW}{cleaned_domain}")

    # Filter pattern for sensitive extensions
    extensions = [
        ".xls", ".xml", ".xlsx", ".json", ".pdf", ".sql", ".doc", ".docx",
        ".pptx", ".txt", ".zip", ".tar.gz", ".tgz", ".bak", ".7z", ".rar",
        ".log", ".cache", ".secret", ".db", ".backup", ".yml", ".gz", ".config",
        ".csv", ".yaml", ".md", ".md5", ".exe", ".dll", ".bin", ".ini", ".bat",
        ".sh", ".tar", ".deb", ".rpm", ".iso", ".img", ".apk", ".msi", ".dmg",
        ".tmp", ".crt", ".pem", ".key", ".pub", ".asc"
    ]
    pattern = r'(' + '|'.join(map(re.escape, extensions)) + r')(\?|#|$)'
    regex = re.compile(pattern, re.IGNORECASE)

    # Fetch URLs from both sources
    print(f"{Fore.CYAN}[+] Fetching Wayback Machine URLs...")
    archive_urls = fetch_archived_urls(cleaned_domain)

    print(f"{Fore.CYAN}[+] Fetching OTX AlienVault URLs...")
    otx_urls = fetch_otx_urls(cleaned_domain)

    # Process and deduplicate
    all_urls = list(set(archive_urls + otx_urls))
    print(f"{Fore.GREEN}[+] Total URLs found: {len(all_urls)}")

    # Filter URLs
    filtered = []
    normal = []
    for url in all_urls:
        if regex.search(url):
            filtered.append(url)
        else:
            normal.append(url)

    # Save results
    if args.output:
        # Save normal URLs
        try:
            with open(args.output, 'w') as f:
                f.write('\n'.join(normal))
            print(f"{Fore.GREEN}[+] Saved {len(normal)} normal URLs to: {args.output}")
        except Exception as e:
            print(f"{Fore.RED}[-] Error saving normal URLs: {e}")

        # Save filtered URLs
        filtered_file = Path(args.output).with_stem(f"{Path(args.output).stem}_filtered")
        try:
            with open(filtered_file, 'w') as f:
                f.write('\n'.join(filtered))
            print(f"{Fore.GREEN}[+] Saved {len(filtered)} filtered URLs to: {filtered_file}")
        except Exception as e:
            print(f"{Fore.RED}[-] Error saving filtered URLs: {e}")
    else:
        # Print normal URLs
        print(f"\n{Fore.CYAN}[+] Normal URLs ({len(normal)}):")
        for url in normal:
            print(f"  {Fore.WHITE}{url}")

        # Save filtered URLs to default file
        try:
            with open("filtered_urls.txt", 'w') as f:
                f.write('\n'.join(filtered))
            print(f"\n{Fore.GREEN}[+] Saved {len(filtered)} filtered URLs to: filtered_urls.txt")
        except Exception as e:
            print(f"{Fore.RED}[-] Error saving filtered URLs: {e}")