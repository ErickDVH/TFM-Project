import requests
import whois
import socket
import ssl
from bs4 import BeautifulSoup
import time
import random
from urllib.parse import urlparse
from colorama import Fore, Style, Back, init
import csv
import os

init(autoreset=True)

# Function to search on Google using Google Custom Search API
def google_custom_search(query, api_key, cx):
    params = {
        'key': api_key,
        'cx': cx,
        'q': query
    }
    try:
        response = requests.get("https://www.googleapis.com/customsearch/v1", params=params)
        response.raise_for_status()
        json_response = response.json()
        if 'items' in json_response:
            results = json_response['items']
            links = [item['link'] for item in results if 'link' in item]
            return links
        else:
            print("No results found in the response.")
            return []
    except requests.RequestException as e:
        print("Connection error:", e)
        return []

# Function to search for subdomains using crt.sh
def search_subdomains(domain):
    try:
        response = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json")
        response.raise_for_status()
        subdomains = set(entry['name_value'] for entry in response.json())
        return subdomains
    except requests.RequestException as e:
        print("Connection error:", e)
        return set()

# Function to analyze DNS records
def analyze_dns(domain):
    try:
        dns_response = socket.gethostbyname_ex(domain)
        return {'Record Type': dns_response[0], 'Data': dns_response[2]} if dns_response[2] else None
    except socket.gaierror as e:
        print("Error resolving domain:", e)
        return None

# Function to get WHOIS information
def get_whois_info(domain):
    try:
        whois_info = whois.whois(domain)
        return whois_info
    except Exception as e:
        print("Error retrieving WHOIS information:", e)
        return None

# Function to get SSL certificates
def get_ssl_certificates(domain):
    try:
        ssl_context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with ssl_context.wrap_socket(sock, server_hostname=domain) as ssock:
                certificate = ssock.getpeercert()
                return certificate
    except Exception as e:
        print("Error retrieving SSL/TLS certificates:", e)
        return None

# Function to get links from a webpage using BeautifulSoup
def get_page_links(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        links = set(a['href'] for a in soup.find_all('a', href=True) if a['href'].startswith('http'))
        return links
    except requests.RequestException as e:
        print("Connection error:", e)
        return set()

# Function to get links from Wayback Machine
def get_wayback_links(domain):
    wayback_links = set()
    try:
        response = requests.get(f"https://web.archive.org/cdx/search/cdx?url={domain}&output=json&fl=original")
        response.raise_for_status()
        results = response.json()
        for result in results[1:]:
            wayback_links.add(result[0])
    except requests.RequestException as e:
        print("Connection error:", e)
    return wayback_links

# Function to get external links from Wayback Machine
def get_external_wayback_links(domain):
    wayback_urls = get_wayback_links(domain)
    external_links = set()
    for url in wayback_urls:
        page_links = get_page_links(url)
        for link in page_links:
            link_domain = urlparse(link).netloc
            if domain != link_domain and link_domain:
                external_links.add(link_domain)
        time.sleep(random.uniform(1, 3))  # Adds a small delay between requests
    return external_links

# Function to get social media links
def get_social_media_links(domain, api_key, cx):
    social_links = set()
    social_networks = ["twitter.com", "linkedin.com", "facebook.com", "instagram.com", "youtube.com"]
    for network in social_networks:
        print(f"Searching on {network} for {domain}...")
        query = f"site:{network} {domain}"
        links = google_custom_search(query, api_key, cx)
        if links:
            social_links.update(links)
        time.sleep(random.uniform(1, 3))  # Adds a small delay between requests to avoid rate limit issues
    return social_links

# Function to collect and correlate domain data
def collect_and_correlate_data(domain, api_key, cx, verbose=False):
    print(f"\n{Back.YELLOW}{Fore.BLACK}Collecting Google search results...{Style.RESET_ALL}")
    google_results = google_custom_search(domain, api_key, cx)

    print(f"\n{Back.YELLOW}{Fore.BLACK}Collecting subdomains...{Style.RESET_ALL}")
    subdomains = search_subdomains(domain)

    print(f"\n{Back.YELLOW}{Fore.BLACK}Analyzing DNS records...{Style.RESET_ALL}")
    dns_response = analyze_dns(domain)

    print(f"\n{Back.YELLOW}{Fore.BLACK}Retrieving WHOIS information...{Style.RESET_ALL}")
    whois_info = get_whois_info(domain)

    print(f"\n{Back.YELLOW}{Fore.BLACK}Retrieving SSL/TLS certificates...{Style.RESET_ALL}")
    certificate = get_ssl_certificates(domain)

    print(f"\n{Back.YELLOW}{Fore.BLACK}Searching for external links on Wayback Machine...{Style.RESET_ALL}")
    external_wayback_links = get_external_wayback_links(domain)

    print(f"\n{Back.YELLOW}{Fore.BLACK}Searching for social media links...{Style.RESET_ALL}")
    social_media_links = get_social_media_links(domain, api_key, cx)

    if verbose:
        print(f"\n{Back.GREEN}{Fore.BLACK}Google results found for {domain}:{Style.RESET_ALL}")
        for result in google_results:
            print(f"{Fore.LIGHTBLUE_EX}{result}{Style.RESET_ALL}")

        print(f"\n{Back.GREEN}{Fore.BLACK}Subdomains found for {domain}:{Style.RESET_ALL}")
        for sub in subdomains:
            print(f"{Fore.LIGHTBLUE_EX}{sub}{Style.RESET_ALL}")

        if dns_response:
            print(f"\n{Back.GREEN}{Fore.BLACK}DNS records found for {domain}:{Style.RESET_ALL}")
            for key, value in dns_response.items():
                print(f"{Fore.LIGHTBLUE_EX}{key}: {value}{Style.RESET_ALL}")
        else:
            print(f"{Back.RED}{Fore.BLACK}No DNS records found for {domain}.{Style.RESET_ALL}")

        if whois_info:
            print(f"\n{Back.GREEN}{Fore.BLACK}WHOIS information found for {domain}:{Style.RESET_ALL}")
            for key, value in whois_info.items():
                print(f"{Fore.LIGHTBLUE_EX}{key}: {value}{Style.RESET_ALL}")
        else:
            print(f"{Back.RED}{Fore.BLACK}No WHOIS information found for {domain}.{Style.RESET_ALL}")

        if certificate:
            print(f"\n{Back.GREEN}{Fore.BLACK}SSL/TLS certificate found for {domain}:{Style.RESET_ALL}")
            for key, value in certificate.items():
                print(f"{Fore.LIGHTBLUE_EX}{key}: {value}{Style.RESET_ALL}")
        else:
            print(f"{Back.RED}{Fore.BLACK}No SSL/TLS certificates found for {domain}.{Style.RESET_ALL}")

        print(f"\n{Back.GREEN}{Fore.BLACK}External links found on Wayback Machine for {domain}:{Style.RESET_ALL}")
        for link in external_wayback_links:
            print(f"{Fore.LIGHTBLUE_EX}{link}{Style.RESET_ALL}")

        print(f"\n{Back.GREEN}{Fore.BLACK}Social media links found for {domain}:{Style.RESET_ALL}")
        for link in social_media_links:
            print(f"{Fore.LIGHTBLUE_EX}{link}{Style.RESET_ALL}")
    else:
        # Minimalistic mode
        print(f"\n{Back.GREEN}{Fore.BLACK}Summary of collected data for {domain}:{Style.RESET_ALL}")
        print(f"{Fore.LIGHTBLUE_EX}Google Results: {len(google_results)}{Style.RESET_ALL}")
        print(f"{Fore.LIGHTBLUE_EX}Subdomains: {len(subdomains)}{Style.RESET_ALL}")
        print(f"{Fore.LIGHTBLUE_EX}DNS Records: {len(dns_response) if dns_response else 0}{Style.RESET_ALL}")
        print(f"{Fore.LIGHTBLUE_EX}WHOIS Information: {len(whois_info) if whois_info else 0}{Style.RESET_ALL}")
        print(f"{Fore.LIGHTBLUE_EX}SSL/TLS Certificate: {'Yes' if certificate else 'No'}{Style.RESET_ALL}")
        print(f"{Fore.LIGHTBLUE_EX}External Wayback Links: {len(external_wayback_links)}{Style.RESET_ALL}")
        print(f"{Fore.LIGHTBLUE_EX}Social Media Links: {len(social_media_links)}{Style.RESET_ALL}")

    return {
        'google_results': google_results,
        'subdomains': subdomains,
        'dns_response': dns_response,
        'whois_info': whois_info,
        'certificate': certificate,
        'external_wayback_links': external_wayback_links,
        'social_media_links': social_media_links
    }

# Function to automatically find related domains with WayBack Machine
def find_related_domains_WayBackMachine(main_domain):
    results = get_external_wayback_links(main_domain)
    related_domains = set()

    # List of domains to exclude (social networks and other non-relevant domains)
    excluded_domains = {
        'www.youtube.com', 'www.facebook.com', 'www.instagram.com', 'www.twitter.com', 'www.linkedin.com', 'www.pinterest.com', 'www.tiktok.com',
        'youtube.com', 'facebook.com', 'instagram.com', 'twitter.com', 'linkedin.com', 'pinterest.com', 'tiktok.com', 'es-es.facebook.com', 'es-linkedin.com'
    }
    for result in results:
        # Filter out excluded and main domains
        if main_domain not in result:
            if result and result != main_domain and result not in excluded_domains:
                related_domains.add(result)
    
    return list(related_domains)

# Function to automatically find related domains using Google
def find_related_domains_Google(main_domain, api_key, cx):
    query = f"site:{main_domain}"
    results = google_custom_search(query, api_key, cx)
    related_domains = set()
    
    # List of domains to exclude (social networks and other non-relevant domains)
    excluded_domains = {
        'www.youtube.com', 'www.facebook.com', 'www.instagram.com', 'www.twitter.com', 'www.linkedin.com', 'www.pinterest.com', 'www.tiktok.com',
        'youtube.com', 'facebook.com', 'instagram.com', 'twitter.com', 'linkedin.com', 'pinterest.com', 'tiktok.com', 'es-es.facebook.com', 'es-linkedin.com'
    }

    for result in results:
        found_domain = urlparse(result).netloc
        # Filter out excluded and main domains
        if found_domain and found_domain != main_domain and found_domain not in excluded_domains:
            related_domains.add(found_domain)
    
    return list(related_domains)

# Function to read domains from a CSV file
def read_domains_csv(file_name):
    try:
        with open(file_name, mode='r', newline='', encoding='utf-8') as file:
            csv_reader = csv.reader(file)
            domains = [row[0] for row in csv_reader if row]
            return domains
    except Exception as e:
        print("Error reading the CSV file:", e)
        return []
    
# Function to compare domains
def compare_domains(domain1, domain2):

    # Comparison of Google search results
    print(f"\n{Fore.BLUE}Comparison of Google search results:{Style.RESET_ALL}")
    if domain1.get('google_results') and domain2.get('google_results'):
        common = set(domain1['google_results']).intersection(set(domain2['google_results']))
        if common:
            print(f"{Fore.YELLOW}Common Google results: {Fore.GREEN}{common}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}No common Google search results found between the domains.{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}No Google search results found for one or both domains.{Style.RESET_ALL}")

    # Comparison of subdomains
    print(f"\n{Fore.BLUE}Comparison of subdomains:{Style.RESET_ALL}")
    if domain1.get('subdomains') and domain2.get('subdomains'):
        common = set(domain1['subdomains']).intersection(set(domain2['subdomains']))
        if common:
            print(f"{Fore.YELLOW}Common subdomains: {Fore.GREEN}{common}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}No common subdomains found between the domains.{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}No subdomains found for one or both domains.{Style.RESET_ALL}")
        
    # Comparison of WHOIS information
    print(f"{Fore.BLUE}Comparison of WHOIS information:{Style.RESET_ALL}")

    if domain1.get('whois_info') and domain2.get('whois_info'):
        if all(value is None for value in domain1['whois_info'].values()) and all(value is None for value in domain2['whois_info'].values()):
            print(f"{Fore.RED}No valid WHOIS information found for either domain.{Style.RESET_ALL}")
        else:
            for key in domain1['whois_info']:
                if key in domain2['whois_info']:
                    print(f"{Fore.YELLOW}{key}:{Style.RESET_ALL}")
                    print(f"  {Fore.GREEN}Domain 1: {domain1['whois_info'].get(key, 'Not available')}{Style.RESET_ALL}")
                    print(f"  {Fore.GREEN}Domain 2: {domain2['whois_info'].get(key, 'Not available')}{Style.RESET_ALL}")
    else:
        if not domain1.get('whois_info'):
            print(f"{Fore.RED}No WHOIS information found for Domain 1.{Style.RESET_ALL}")
        if not domain2.get('whois_info'):
            print(f"{Fore.RED}No WHOIS information found for Domain 2.{Style.RESET_ALL}")

    # Comparison of DNS records
    print(f"\n{Fore.BLUE}Comparison of DNS records:{Style.RESET_ALL}")
    if domain1.get('dns_response') and domain2.get('dns_response'):
        for key in domain1['dns_response']:
            if key in domain2['dns_response']:
                print(f"{Fore.YELLOW}{key}:{Style.RESET_ALL}")
                print(f"  {Fore.GREEN}Domain 1: {domain1['dns_response'].get(key, 'Not available')}{Style.RESET_ALL}")
                print(f"  {Fore.GREEN}Domain 2: {domain2['dns_response'].get(key, 'Not available')}{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}No DNS records found for one or both domains.{Style.RESET_ALL}")

    # Comparison of SSL/TLS certificates
    print(f"\n{Fore.BLUE}Comparison of SSL/TLS certificates:{Style.RESET_ALL}")
    if domain1.get('certificate') and domain2.get('certificate'):
        for key in domain1['certificate']:
            if key in domain2['certificate']:
                print(f"{Fore.YELLOW}{key}:{Style.RESET_ALL}")
                print(f"  {Fore.GREEN}Domain 1: {domain1['certificate'].get(key, 'Not available')}{Style.RESET_ALL}")
                print(f"  {Fore.GREEN}Domain 2: {domain2['certificate'].get(key, 'Not available')}{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}No SSL/TLS certificates found for one or both domains.{Style.RESET_ALL}")

    # Comparison of external links in Wayback Machine
    print(f"\n{Fore.BLUE}Comparison of external links in Wayback Machine:{Style.RESET_ALL}")
    if domain1.get('external_links_wayback') and domain2.get('external_links_wayback'):
        common = domain1['external_links_wayback'].intersection(domain2['external_links_wayback'])
        if common:
            print(f"{Fore.YELLOW}Common links: {Fore.GREEN}{common}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}No common links found between the domains.{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}No links found in Wayback Machine for one or both domains.{Style.RESET_ALL}")

    # Comparison of social media links
    print(f"\n{Fore.BLUE}Comparison of social media links:{Style.RESET_ALL}")
    if domain1.get('social_media_links') and domain2.get('social_media_links'):
        common = domain1['social_media_links'].intersection(domain2['social_media_links'])
        if common:
            print(f"{Fore.YELLOW}Common social media links: {Fore.GREEN}{common}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}No common social media links found between the domains.{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}No social media links found for one or both domains.{Style.RESET_ALL}")

# Function for simple domain comparison
def compare_domains_simple(domain1, domain2):
    # Initialize counters
    total_criteria = 0
    matches = 0

    # Get domain names, handle if they don't exist
    domain_name1 = domain1.get('domain', 'Domain 1')
    domain_name2 = domain2.get('domain', 'Domain 2')

    # WHOIS information comparison
    print(f"\n{Fore.BLUE}WHOIS information comparison:{Style.RESET_ALL}")
    if domain1.get('whois_info') and domain2.get('whois_info'):
        for key, value1 in domain1['whois_info'].items():
            value2 = domain2['whois_info'].get(key)
            total_criteria += 1
            if value1 and value2 and value1 == value2:
                print(f"{Fore.GREEN}WHOIS match: {key} - {value1}{Style.RESET_ALL}")
                matches += 1
            else:
                print(f"{Fore.YELLOW}No WHOIS match for {key}. {domain_name1}: {value1}, {domain_name2}: {value2}{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}No WHOIS information found for one or both domains.{Style.RESET_ALL}")
        total_criteria += 1  # Increment to reflect this criterion was evaluated

    # DNS records comparison
    print(f"\n{Fore.BLUE}DNS records comparison:{Style.RESET_ALL}")
    if domain1.get('dns_response') and domain2.get('dns_response'):
        for key, value1 in domain1['dns_response'].items():
            value2 = domain2['dns_response'].get(key)
            total_criteria += 1
            if value1 and value2 and value1 == value2:
                print(f"{Fore.GREEN}DNS match: {key} - {value1}{Style.RESET_ALL}")
                matches += 1
            else:
                print(f"{Fore.YELLOW}No DNS match for {key}. {domain_name1}: {value1}, {domain_name2}: {value2}{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}No DNS records found for one or both domains.{Style.RESET_ALL}")
        total_criteria += 1  # Increment to reflect this criterion was evaluated

    # SSL/TLS certificates comparison
    print(f"\n{Fore.BLUE}SSL/TLS certificates comparison:{Style.RESET_ALL}")
    if domain1.get('certificate') and domain2.get('certificate'):
        for key, value1 in domain1['certificate'].items():
            value2 = domain2['certificate'].get(key)
            total_criteria += 1
            if value1 and value2 and value1 == value2:
                print(f"{Fore.GREEN}SSL/TLS match: {key} - {value1}{Style.RESET_ALL}")
                matches += 1
            else:
                print(f"{Fore.YELLOW}No SSL/TLS match for {key}. {domain_name1}: {value1}, {domain_name2}: {value2}{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}No SSL/TLS certificates found for one or both domains.{Style.RESET_ALL}")
        total_criteria += 1  # Increment to reflect this criterion was evaluated

    # Calculate match percentage
    if total_criteria > 0:
        match_percentage = (matches / total_criteria) * 100
        print(f"\n{Fore.YELLOW}Match percentage between {domain_name1} and {domain_name2}: {Fore.GREEN}{match_percentage:.2f}%{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}No sufficient criteria found to compare.{Style.RESET_ALL}")

    # Ensure always having a result even if there are no matches
    if matches == 0 and total_criteria > 0:
        print(f"{Fore.RED}No matches found between {domain_name1} and {domain_name2}.{Style.RESET_ALL}")


# Function to save results to a CSV file
def save_to_csv(data, filename):
    try:
        with open(filename, mode='w', newline='', encoding='utf-8') as file:
            csv_writer = csv.writer(file)
            csv_writer.writerow(['Domain', 'Google Results', 'Subdomains', 'DNS Records', 'WHOIS Information', 'SSL/TLS Certificate', 'Wayback Machine External Links', 'Social Media Links'])
            for result in data:
                csv_writer.writerow([
                    result.get('domain', ''),
                    len(result.get('google_results', [])),
                    len(result.get('subdomains', [])),
                    result.get('dns_response') is not None,
                    result.get('whois_info') is not None,
                    result.get('certificate') is not None,
                    len(result.get('external_links_wayback', [])),
                    len(result.get('social_media_links', []))
                ])
    except Exception as e:
        print("Error saving to CSV file:", e)

# Tool execution
if __name__ == "__main__":
    # Request Google Custom Search API key
    while True:
        api_key = input("Enter your Google Custom Search API key: ").strip()
        if api_key:
            break
        print(f"{Back.RED}{Fore.BLACK}Invalid API key. Please enter a valid value.{Style.RESET_ALL}")
    
    # Request custom search ID (CX)
    while True:
        cx = input("Enter the custom search ID (CX): ").strip()
        if cx:
            break
        print(f"{Back.RED}{Fore.BLACK}Invalid custom search ID (CX). Please enter a valid value.{Style.RESET_ALL}")
    
    # Request operation mode
    while True:
        mode = input("Do you want to analyze one domain or multiple domains from a CSV file? (one/multiple): ").strip().lower()
        if mode in ["one", "multiple"]:
            break
        print(f"{Back.RED}{Fore.BLACK}Unrecognized mode. Please choose 'one' or 'multiple'.{Style.RESET_ALL}")

    if mode == "one":
        # Request the main domain to analyze
        while True:
            main_domain = input("Enter the main domain to analyze: ").strip()
            if main_domain:
                break
            print(f"{Back.RED}{Fore.BLACK}Invalid main domain.{Style.RESET_ALL}")

        # Ask if detailed output is desired
        verbose = input("Do you want detailed output? (yes/no): ").strip().lower() == "yes"

        try:
            # Collect and correlate data from the main domain
            main_domain_data = collect_and_correlate_data(main_domain, api_key, cx, verbose=verbose)

            # Domain comparison options
            while True:
                comparison_option = input("\nDo you want to make domain comparisons with details (Google)? (yes/no): ").strip().lower()
                if comparison_option in ["yes", "no"]:
                    break
                print(f"{Back.RED}{Fore.BLACK}Invalid option. Please choose 'yes' or 'no'.{Style.RESET_ALL}")

            if comparison_option == "yes":
                # Automatically find related domains
                related_domains = find_related_domains_Google(main_domain, api_key, cx)
                if related_domains:
                    print(f"\n{Back.GREEN}{Fore.BLACK}Related domains found:{Style.RESET_ALL}")
                    for domain in related_domains:
                        print(f"{Fore.LIGHTBLUE_EX}{domain}{Style.RESET_ALL}")

                    for domain in related_domains:
                        print(f"\n{Back.GREEN}{Fore.BLACK}Collecting data for related domain: {domain}{Style.RESET_ALL}")
                        related_domain_data = collect_and_correlate_data(domain, api_key, cx, verbose=verbose)
                        print(f"\n{Back.CYAN}{Fore.BLACK}Comparison between {main_domain} and {domain}:{Style.RESET_ALL}")
                        compare_domains(main_domain_data, related_domain_data)
                else:
                    print(f"{Back.RED}{Fore.BLACK}No related domains found.{Style.RESET_ALL}")

            else:
                # Ask if simple comparisons are desired
                while True:
                    simple_comparison_option = input("\nDo you want to make simple domain comparisons (WayBack Machine)? (yes/no): ").strip().lower()
                    if simple_comparison_option in ["yes", "no"]:
                        break
                    print(f"{Back.RED}{Fore.BLACK}Invalid option. Please choose 'yes' or 'no'.{Style.RESET_ALL}")

                if simple_comparison_option == "yes":
                    # Automatically find related domains without details
                    related_domains = find_related_domains_WayBackMachine(main_domain)
                    if related_domains:
                        print(f"\n{Back.GREEN}{Fore.BLACK}Related domains found:{Style.RESET_ALL}")
                        for domain in related_domains:
                            print(f"{Fore.LIGHTBLUE_EX}{domain}{Style.RESET_ALL}")

                        for domain in related_domains:
                            print(f"\n{Back.GREEN}{Fore.BLACK}Collecting data for related domain: {domain}{Style.RESET_ALL}")
                            related_domain_data = collect_and_correlate_data(domain, api_key, cx, verbose=verbose)
                            print(f"\n{Back.CYAN}{Fore.BLACK}Comparison between {main_domain} and {domain}:{Style.RESET_ALL}")
                            compare_domains_simple(main_domain_data, related_domain_data)
                    else:
                        print(f"{Back.RED}{Fore.BLACK}No related domains found.{Style.RESET_ALL}")

                else:
                    print(f"\n{Back.YELLOW}{Fore.BLACK}No domain comparisons will be made.{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Back.RED}{Fore.BLACK}An error occurred: {e}{Style.RESET_ALL}")

    elif mode == "multiple":
        # Request the CSV file name
        while True:
            csv_file = input("Enter the CSV file name with domains: ").strip()
            if os.path.isfile(csv_file):
                break
            print(f"{Back.RED}{Fore.BLACK}The CSV file does not exist or is not accessible. Please enter a valid file.{Style.RESET_ALL}")

        domains = read_domains_csv(csv_file)

        if domains:
            results = []
            for domain in domains:
                if domain:
                    try:
                        print(f"\n{Back.GREEN}{Fore.BLACK}Collecting data for domain: {domain}{Style.RESET_ALL}")
                        data = collect_and_correlate_data(domain, api_key, cx, verbose=True)
                        results.append({'domain': domain, **data})
                    except Exception as e:
                        print(f"{Back.RED}{Fore.BLACK}Error processing domain {domain}: {e}{Style.RESET_ALL}")

            # Request the output CSV file name
            while True:
                output_csv_file = input("Enter the output CSV file name to save the results: ").strip()
                if output_csv_file:
                    try:
                        save_to_csv(results, output_csv_file)
                        print(f"{Back.GREEN}{Fore.BLACK}Results saved in {output_csv_file}.{Style.RESET_ALL}")
                        break
                    except Exception as e:
                        print(f"{Back.RED}{Fore.BLACK}Error saving results to CSV file: {e}{Style.RESET_ALL}")
                else:
                    print(f"{Back.RED}{Fore.BLACK}Invalid output CSV file name.{Style.RESET_ALL}")
        else:
            print(f"{Back.RED}{Fore.BLACK}No domains found in the CSV file.{Style.RESET_ALL}")
