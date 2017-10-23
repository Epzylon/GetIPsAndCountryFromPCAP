#!/usr/bin/python

from scapy.all import rdpcap
from GeoIP import new, GEOIP_MEMORY_CACHE
import GeoIP

db = new(GeoIP.GEOIP_MEMORY_CACHE)

pcap = rdpcap('Attack.pcap')
result = open('Attack.csv','w')

for packet in pcap:
	try:
		ip = str(packet[1].src)
	except:
		continue
	country = str(db.country_name_by_addr(ip)).replace(' ','_')
	result.write(ip+";"+country+"\n")
	print(ip+" "+country)

result.close()