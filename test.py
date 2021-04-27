

from ip2geotools.databases.commercial import DbIpCity

country1 = DbIpCity.get("137.132.250.14", api_key='free').country

print(country1)