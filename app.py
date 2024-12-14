from flask import Flask, render_template, request, redirect, url_for
import socket
import dns.resolver
import requests

app = Flask(__name__)

def get_dns_records(domain):
    records = {}
    try:
        # A record
        a_records = dns.resolver.resolve(domain, 'A')
        records['A'] = [str(ip) for ip in a_records]

        # AAAA record
        try:
            aaaa_records = dns.resolver.resolve(domain, 'AAAA')
            records['AAAA'] = [str(ip) for ip in aaaa_records]
        except dns.resolver.NoAnswer:
            records['AAAA'] = []

        # MX record
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            records['MX'] = [str(mx.exchange) for mx in mx_records]
        except dns.resolver.NoAnswer:
            records['MX'] = []

        # TXT record
        try:
            txt_records = dns.resolver.resolve(domain, 'TXT')
            records['TXT'] = [str(txt.strings[0], 'utf-8') for txt in txt_records]
        except dns.resolver.NoAnswer:
            records['TXT'] = []

        # NS record (Name Server)
        try:
            ns_records = dns.resolver.resolve(domain, 'NS')
            records['NS'] = [str(ns.target) for ns in ns_records]
        except dns.resolver.NoAnswer:
            records['NS'] = []

        # CNAME record (Canonical Name)
        try:
            cname_records = dns.resolver.resolve(domain, 'CNAME')
            records['CNAME'] = [str(cname.target) for cname in cname_records]
        except dns.resolver.NoAnswer:
            records['CNAME'] = []

        # SOA record (Start of Authority)
        try:
            soa_records = dns.resolver.resolve(domain, 'SOA')
            records['SOA'] = [str(soa.mname) for soa in soa_records]
        except dns.resolver.NoAnswer:
            records['SOA'] = []

        # PTR record (Reverse DNS)
        try:
            ptr_records = dns.resolver.resolve(domain, 'PTR')
            records['PTR'] = [str(ptr.target) for ptr in ptr_records]
        except dns.resolver.NoAnswer:
            records['PTR'] = []

        return records
    except Exception as e:
        return {"error": str(e)}

def get_ip_info(ip):
    info = {}
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        data = response.json()
        info['IP'] = ip
        info['Country'] = data.get('country')
        info['Region'] = data.get('region')
        info['City'] = data.get('city')
        info['Provider'] = data.get('org')
        info['Hostname'] = data.get('hostname')
    except Exception as e:
        info['IP Info Error'] = str(e)
    return info

def get_google_dork_links(domain):
    dorks = {
        "Sensitive Information Dorks": [
            f"https://www.google.com/search?q=filetype:csv+%22username,+password%22+site:{domain}",
            f"https://www.google.com/search?q=filetype:xls+%22password%22+site:{domain}",
            f"https://www.google.com/search?q=filetype:txt+%22password%22+site:{domain}",
            f"https://www.google.com/search?q=filetype:log+%22password%22+site:{domain}",
            f"https://www.google.com/search?q=filetype:bak+%22password%22+site:{domain}",
            f"https://www.google.com/search?q=filetype:xml+%22password%22+site:{domain}",
            f"https://www.google.com/search?q=filetype:json+%22password%22+site:{domain}",
            f"https://www.google.com/search?q=filetype:db+%22password%22+site:{domain}",
            f"https://www.google.com/search?q=filetype:pdf+%22username+password%22+site:{domain}",
        ],
        "Sensitive Directories & Files": [
            f"https://www.google.com/search?q=intitle:%22index+of%22+%22mysql%22+site:{domain}",
            f"https://www.google.com/search?q=intitle:%22index+of%22+%22admin%22+site:{domain}",
            f"https://www.google.com/search?q=intitle:%22index+of%22+%22config%22+site:{domain}",
            f"https://www.google.com/search?q=intitle:%22index+of%22+%22backup%22+site:{domain}",
            f"https://www.google.com/search?q=intitle:%22index+of%22+%22secrets%22+site:{domain}",
            f"https://www.google.com/search?q=intitle:%22index+of%22+%22logs%22+site:{domain}",
            f"https://www.google.com/search?q=intitle:%22index+of%22+%22database%22+site:{domain}",
            f"https://www.google.com/search?q=intitle:%22index+of%22+%22credentials%22+site:{domain}",
        ],
        "Admin Panel Dorks": [
            f"https://www.google.com/search?q=inurl:%22admin%22+site:{domain}",
            f"https://www.google.com/search?q=inurl:%22login%22+%22admin%22+site:{domain}",
            f"https://www.google.com/search?q=inurl:%22wp-admin%22+site:{domain}",
            f"https://www.google.com/search?q=inurl:%22admin%22+%22panel%22+site:{domain}",
            f"https://www.google.com/search?q=inurl:%22cpanel%22+site:{domain}",
            f"https://www.google.com/search?q=inurl:%22admin-login%22+site:{domain}",
            f"https://www.google.com/search?q=inurl:%22admin%22+%22dashboard%22+site:{domain}",
        ],
        "Files with Possible Credentials": [
            f"https://www.google.com/search?q=filetype:env+%22database_url%22+site:{domain}",
            f"https://www.google.com/search?q=filetype:env+%22db_password%22+site:{domain}",
            f"https://www.google.com/search?q=filetype:json+%22access_key%22+site:{domain}",
            f"https://www.google.com/search?q=filetype:env+%22secret_key%22+site:{domain}",
            f"https://www.google.com/search?q=filetype:ini+%22password%22+site:{domain}",
            f"https://www.google.com/search?q=filetype:json+%22token%22+site:{domain}",
            f"https://www.google.com/search?q=filetype:xml+%22username%22+%22password%22+site:{domain}",
        ],
        "Backup and Configuration Files": [
            f"https://www.google.com/search?q=intitle:%22index+of%22+%22backup%22+site:{domain}",
            f"https://www.google.com/search?q=filetype:bak+%22backup%22+site:{domain}",
            f"https://www.google.com/search?q=filetype:sql+%22database+backup%22+site:{domain}",
            f"https://www.google.com/search?q=filetype:tar+%22backup%22+site:{domain}",
            f"https://www.google.com/search?q=filetype:zip+%22backup%22+site:{domain}",
            f"https://www.google.com/search?q=filetype:sql+%22dump%22+site:{domain}",
        ],
        "Vulnerable Files": [
            f"https://www.google.com/search?q=filetype:php+%22eval%22+site:{domain}",
            f"https://www.google.com/search?q=filetype:php+%22base64_decode%22+site:{domain}",
            f"https://www.google.com/search?q=filetype:js+%22eval%22+site:{domain}",
            f"https://www.google.com/search?q=filetype:php+%22system%22+site:{domain}",
            f"https://www.google.com/search?q=filetype:php+%22shell_exec%22+site:{domain}",
            f"https://www.google.com/search?q=filetype:php+%22exec%22+site:{domain}",
        ],
        "Hidden Login Pages": [
            f"https://www.google.com/search?q=inurl:%22admin-login%22+site:{domain}",
            f"https://www.google.com/search?q=inurl:%22login%22+%22admin%22+site:{domain}",
            f"https://www.google.com/search?q=inurl:%22auth%22+%22login%22+site:{domain}",
            f"https://www.google.com/search?q=inurl:%22signin%22+site:{domain}",
            f"https://www.google.com/search?q=inurl:%22login%22+%22dashboard%22+site:{domain}",
        ],
        "Server Files and Configuration": [
            f"https://www.google.com/search?q=filetype:conf+%22server%22+site:{domain}",
            f"https://www.google.com/search?q=filetype:conf+%22nginx%22+site:{domain}",
            f"https://www.google.com/search?q=filetype:conf+%22apache%22+site:{domain}",
            f"https://www.google.com/search?q=filetype:json+%22config%22+site:{domain}",
        ],
                    
        "Default Pages and Login Forms": [
            f"https://www.google.com/search?q=inurl:%22default%22+%22login%22+site:{domain}",
            f"https://www.google.com/search?q=inurl:%22login%22+%22wp-login.php%22+site:{domain}",
            f"https://www.google.com/search?q=inurl:%22admin%22+%22login%22+site:{domain}",
        ]
    }
    return dorks





@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        domain_name = request.form.get("domain")
        return redirect(url_for("results", domain=domain_name))
    return render_template("index.html")

@app.route("/results")
def results():
    domain_name = request.args.get("domain")
    dns_records = None
    ip_info = None
    dork_links = None
    
    error = None

    try:
        # DNS records
        dns_records = get_dns_records(domain_name)

        # IP info
        ip = socket.gethostbyname(domain_name)
        ip_info = get_ip_info(ip)

        # Google Dorks
        dork_links = get_google_dork_links(domain_name)

        
    except Exception as e:
        error = str(e)

    return render_template(
        "results.html",
        domain=domain_name,
        dns_records=dns_records,
        ip_info=ip_info,
        dork_links=dork_links,
        
        error=error
    )

if __name__ == "__main__":
    app.run(debug=True)