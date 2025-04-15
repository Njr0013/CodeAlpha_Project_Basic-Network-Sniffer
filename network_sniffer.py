
import socket
import struct
import binascii

# IP header parsing function
def parse_ip_header(data):
    ip_hdr = struct.unpack('!BBHHHBBH4s4s', data[:20])
    version_ihl = ip_hdr[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    ttl = ip_hdr[5]
    protocol = ip_hdr[6]
    src_addr = socket.inet_ntoa(ip_hdr[8])
    dst_addr = socket.inet_ntoa(ip_hdr[9])

    print(f"\nIP Header:")
    print(f" Version: {version}")
    print(f" Header Length: {ihl * 4} bytes")
    print(f" TTL: {ttl}")
    print(f" Protocol: {protocol}")
    print(f" Source IP: {src_addr}")
    print(f" Destination IP: {dst_addr}")

# Main function to sniff packets
def sniff():
    # Create raw socket (IPv4, raw mode, all protocols)
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

    # Bind to local interface
    host = socket.gethostbyname(socket.gethostname())
    sniffer.bind((host, 0))

    # Include IP headers
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # Windows: enable promiscuous mode
    try:
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    except AttributeError:
        pass  # On Unix/Linux, it's already promiscuous by default when using raw sockets

    print(f"[*] Sniffing on {host}... Press Ctrl+C to stop.")

    try:
        while True:
            raw_data, addr = sniffer.recvfrom(65535)
            parse_ip_header(raw_data)
    except KeyboardInterrupt:
        print("\n[!] Stopped packet sniffing.")
        try:
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        except AttributeError:
            pass

if __name__ == "__main__":
    sniff()
