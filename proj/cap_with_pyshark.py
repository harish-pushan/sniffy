from pyshark import LiveCapture


def cap_wireshark():
    try:
        network_interface = 'wlan0'
        capture = LiveCapture(
            interface=network_interface,
            output_file="capture.pcap"
        )
        for packet in capture.sniff_continuously():
            print(packet)
    except KeyboardInterrupt:
        print("Capture stopped.")


cap_wireshark()
