# Dork_Hunter - Advanced DNS Lookup Tool

**Dork_Hunter** is a powerful web tool designed to provide users with in-depth DNS records, domain information, and IP details for any given domain. It serves as an invaluable resource for cybersecurity researchers, ethical hackers, and anyone interested in gaining insights into a domain's online presence. The tool also provides relevant Google dork links to assist in further investigation.

## Features
- **DNS Records Lookup**: Get detailed DNS records such as A, MX, TXT, and more for any domain.
- **Domain Information**: View essential domain details including registration information.
- **IP Information**: Discover the IP address and geolocation details associated with the domain.
- **Google Dork Links**: Find useful Google dork queries for further research and penetration testing.

## Requirements
- Python 3.x
- Flask (for web framework)


## Installation

### Step 1: Clone the repository

```bash
git clone https://github.com/karthicysec/Top_Dork_Hunter.git
```

### Step 2: Navigate to the project directory

```bash
cd Top_Dork_Hunte.git
```

### Step 3: Install dependencies

```bash
pip install -r requirements.txt
```

## Usage

1. Run the tool locally:

```bash
python app.py
```

2. Open your browser and go to:

```
http://127.0.0.1:5000
```

3. Enter the domain name you want to investigate into the input field and click the **Lookup** button.

4. The tool will display the DNS records, domain information, and IP details for the entered domain.

## Example

1. Input a domain like `example.com`.
2. The tool will fetch and display:
    - DNS records (A, MX, TXT, etc.)
    - Domain info (Whois details, registration info)
    - IP information (location, provider, hostname)
    - Google Dork Links: Find useful Google dork queries for further research and penetration testing.


- Powered by Python and Flask for the web application framework.
- Uses various external APIs for fetching domain and IP information.

---

