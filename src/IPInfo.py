import geoip2.database


def getIP(ip):
    with geoip2.database.Reader('/var/lib/GeoIP/GeoLite2-City.mmdb') as reader:
        response = reader.city(ip)
        locale = []
        if response.city.name:
            locale.append(response.city.name)
        for subdivision in response.subdivisions[::-1]:
            locale.append(subdivision.name)
        if response.country.name:
            locale.append(response.country.name)
        return(", ".join(locale))


def getIPRisk(ip):
    high_risk_countries = {
        'AF': 'Afghanistan',
        'DZ': 'Algeria',
        'AO': 'Angola',
        'BD': 'Bangladesh',
        'BR': 'Brazil',
        'BF': 'Burkina Faso',
        'BI': 'Burundi',
        'KH': 'Cambodia',
        'CM': 'Cameroon',
        'CF': 'Central African Republic',
        'TD': 'Chad',
        'CN': 'China',
        'CD': 'Democratic Republic of the Congo',
        'EG': 'Egypt',
        'ER': 'Eritrea',
        'ET': 'Ethiopia',
        'GM': 'Gambia',
        'GH': 'Ghana',
        'GN': 'Guinea',
        'GW': 'Guinea-Bissau',
        'ID': 'Indonesia',
        'IR': 'Iran',
        'IQ': 'Iraq',
        'CI': 'Ivory Coast',
        'KE': 'Kenya',
        'LA': 'Laos',
        'LB': 'Lebanon',
        'LR': 'Liberia',
        'LY': 'Libya',
        'MG': 'Madagascar',
        'MW': 'Malawi',
        'ML': 'Mali',
        'MR': 'Mauritania',
        'MA': 'Morocco',
        'MM': 'Myanmar',
        'NP': 'Nepal',
        'NE': 'Niger',
        'NG': 'Nigeria',
        'KP': 'North Korea',
        'PK': 'Pakistan',
        'PH': 'Philippines',
        'RU': 'Russia',
        'RW': 'Rwanda',
        'SN': 'Senegal',
        'SL': 'Sierra Leone',
        'SO': 'Somalia',
        'ZA': 'South Africa',
        'SS': 'South Sudan',
        'LK': 'Sri Lanka',
        'SD': 'Sudan',
        'SY': 'Syria',
        'TZ': 'Tanzania',
        'TG': 'Togo',
        'TR': 'Turkey',
        'UG': 'Uganda',
        'UA': 'Ukraine',
        'UZ': 'Uzbekistan',
        'VN': 'Vietnam',
        'YE': 'Yemen',
        'ZM': 'Zambia',
        'ZW': 'Zimbabwe',
    }
    with geoip2.database.Reader('/var/lib/GeoIP/GeoLite2-Country.mmdb') as reader:
        response = reader.country(ip)
        country = response.country.iso_code
        if country in high_risk_countries:
            return "High risk country"
        else:
            return None


def checkRBL(ip):
    rbl_mapping = {
        "127.0.0.2": "Open HTTP Proxy Server",
        "127.0.0.3": "Open SOCKS Proxy Server",
        "127.0.0.4": "Open Proxy Servers",
        "127.0.0.5": "Open SMTP relay Server",
        "127.0.0.6": "Host has been reported as sending spam",
        "127.0.0.7": "Servers which have spammer abusable vulnerabilities",
        "127.0.0.8": "Hosts demanding that they never be tested by SORBS",
        "127.0.0.9": "Network hijacked from their original owners",
        "127.0.0.10": "Dynamic IP Address ranges",
        "127.0.0.11": "A or MX records point to bad address space",
        "127.0.0.12": "No email should ever originate from here",
    }
    import ipaddress
    import dns.resolver
    resolver = dns.resolver.Resolver()
    addr = ipaddress.ip_address(ip)
    if isinstance(addr, ipaddress.IPv6Address):
        longip6 = addr.exploded.replace(':', '')
        reversed_ip = '.'.join(reversed([*longip6]))
    else:
        reversed_ip = '.'.join(reversed(ip.split('.')))
    searchQuery = f"{reversed_ip}.dnsbl.sorbs.net"
    try:
        answer = resolver.resolve(searchQuery, 'A')
        risk = rbl_mapping[str(answer[0])]
    except Exception:
        risk = None
        pass
    return risk
