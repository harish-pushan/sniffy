from nfstream import NFStreamer

# NFStreamer can take a pcap or live interface,
# but for manual integration, you typically use it as a standalone probe.
streamer = NFStreamer(source="wlan0",
                      n_dissections=10,  # Higher value improves L7 accuracy
                      statistical_analysis=True)

for flow in streamer:
    # NFStream uses nDPI to populate the application name and ID
    print(
        f"Flow: {flow.src_ip} -> {flow.dst_ip} | L7 Protocol: {flow.application_name}")

    # If you need to do something in Scapy with this same flow:
    # You can correlate via the 5-tuple (IPs, Ports, Protocol)
