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
