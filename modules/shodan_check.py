import requests


def check_shodan(ip, api_key=None):
    print(f"\nConsultando HackerTarget para {ip}:")
    try:
        r = requests.get(f"https://api.hackertarget.com/geoip/?q={ip}", timeout=5)
        geo = {}
        for line in r.text.split("\n"):
            if ":" in line:
                key, val = line.split(":", 1)
                geo[key.strip()] = val.strip()

        r2 = requests.get(f"https://api.hackertarget.com/hostsearch/?q={ip}", timeout=5)
        hostnames = [h for h in r2.text.split("\n") if h.strip()]

        results = {
            "pais": geo.get("Country", "N/A"),
            "ciudad": geo.get("City", "N/A"),
            "org": geo.get("ASN", "N/A"),
            "hostnames": hostnames[:5]
        }

        print(f"  Pais: {results['pais']}")
        print(f"  Ciudad: {results['ciudad']}")
        print(f"  ASN/Org: {results['org']}")
        if results["hostnames"]:
            for h in results["hostnames"]:
                print(f"  Hostname: {h}")

        return results
    except Exception as e:
        print(f"  Error: {e}")
        return {}