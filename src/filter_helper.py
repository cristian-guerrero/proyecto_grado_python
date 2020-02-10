import scapy.all  as scapy

from scapy.layers import  inet, l2, http


icmp = inet.ICMP

tcp = inet.TCP

ip = inet.IP
http_layer = http.HTTP

request = http.HTTPRequest
response = http.HTTPResponse
