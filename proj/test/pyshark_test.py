import pyshark

# Capture live traffic on a specific interface with a filter
capture = pyshark.LiveCapture(interface='wlan0')
capture.sniff(packet_count=10)

for packet in capture:
    print(packet)
