import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from colorama import init, Fore

# Initialize colorama for colored output
init(autoreset=True)

# SQL Injection payloads
sql_payloads = ["' OR 1=1 --", "' OR 'a'='a", '" OR "a"="a']

# XSS payload
xss_payload = "<script>alert('XSS')</script>"


# Basic web crawler
def crawl(url):
    urls = set()
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        for link in soup.find_all('a'):
            href = link.get('href')
            if href and href.startswith('/'):
                href = urljoin(url, href)
            if href and urlparse(href).netloc == urlparse(url).netloc:
                urls.add(href)
    except Exception as e:
        print(Fore.RED + f"Error crawling {url}: {e}")
    return urls


# Test for SQL Injection vulnerabilities
def test_sql_injection(url):
    print(Fore.YELLOW + "[*] Testing for SQL Injection vulnerabilities...")
    vulnerabilities = []
    for payload in sql_payloads:
        test_url = f"{url}?id={payload}"
        try:
            response = requests.get(test_url)
            if "error" in response.text.lower() or "mysql" in response.text.lower():
                vulnerabilities.append(test_url)
                print(Fore.RED + f"[!] Possible SQL Injection vulnerability found at: {test_url}")
        except Exception as e:
            print(Fore.RED + f"Error testing {test_url}: {e}")
    return vulnerabilities


# Test for XSS vulnerabilities
def test_xss(url):
    print(Fore.YELLOW + "[*] Testing for XSS vulnerabilities...")
    vulnerabilities = []
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action')
            post_url = urljoin(url, action)
            inputs = form.find_all('input')
            data = {}
            for input_tag in inputs:
                name = input_tag.get('name')
                if name:
                    data[name] = xss_payload
            response = requests.post(post_url, data=data)
            if xss_payload in response.text:
                vulnerabilities.append(post_url)
                print(Fore.RED + f"[!] Possible XSS vulnerability found at: {post_url}")
    except Exception as e:
        print(Fore.RED + f"Error testing {url}: {e}")
    return vulnerabilities


# Generate a detailed vulnerability report
def generate_report(vulnerabilities):
    print(Fore.YELLOW + "[*] Generating a detailed vulnerability report...")
    with open('vulnerability_report.html', 'w') as file:
        file.write("<html><body><h1>Vulnerability Report</h1>")
        if vulnerabilities:
            file.write("<h2>SQL Injection Vulnerabilities</h2>")
            if vulnerabilities["SQL Injection"]:
                for url in vulnerabilities["SQL Injection"]:
                    file.write(f"<p>Possible SQL Injection vulnerability found at: {url}</p>")
            else:
                file.write("<p>No SQL Injection vulnerabilities found.</p>")

            file.write("<h2>XSS (Cross-Site Scripting) Vulnerabilities</h2>")
            if vulnerabilities["XSS"]:
                for url in vulnerabilities["XSS"]:
                    file.write(f"<p>Possible XSS vulnerability found at: {url}</p>")
            else:
                file.write("<p>No XSS vulnerabilities found.</p>")
        else:
            file.write("<p>No vulnerabilities found.</p>")
        file.write("</body></html>")
    print(Fore.GREEN + "[*] Detailed vulnerability report generated: vulnerability_report.html")


# Main function
def main():
    url = input("Enter the URL to scan: ")
    urls = crawl(url)
    vulnerabilities = {
        "SQL Injection": [],
        "XSS": []
    }

    for link in urls:
        sql_vulns = test_sql_injection(link)
        xss_vulns = test_xss(link)
        vulnerabilities["SQL Injection"].extend(sql_vulns)
        vulnerabilities["XSS"].extend(xss_vulns)

    generate_report(vulnerabilities)


if __name__ == "__main__":
    main()
