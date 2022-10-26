import sys
from scapy.all import sniff, get_if_addr, conf, srp, sr1, ARP, IP, ICMP, send, Ether, getmacbyip

conf.verb = 0


def help():
    print('''
        
        ---------
        NET RECON
        ---------
        This function allows a user to passively or actively detect hosts on a network
        Args
        ----
        -p INTERFACE: Passive recon on listen interface
        --passive INTERFACE: Passive recon on listening interface
            Example: python net_recon.py -p "Wi-Fi"
        ''')
    return None


scan_results = dict()
host_list = list()


def passive_scan_callback(pkt):
    global scan_results
    global host_list
    # if ARP in pkt and pkt[ARP].op == 1:  # who-has
    #     arp_src = pkt[ARP].psrc
    #     arp_dst = pkt[ARP].pdst
    #     return f"Request: {arp_src} is asking about {arp_dst}"
    if ARP in pkt and pkt[ARP].op == 2:  # who-has
        # print(pkt[ARP].pdst)
        src_mac = pkt[ARP].hwsrc
        src_ip = pkt[ARP].pdst
        print(f"IP: {src_ip} found. MAC: {src_mac}")
        if src_ip in scan_results:
            scan_results[src_ip][0].add(src_mac)
            scan_results[src_ip][1] += 1
            # scan_result[src_ip].extend([src_mac])
        else:
            scan_results[src_ip] = [set([src_mac]), 1]
            # scan_results[src_ip] = set([src_mac])
        host_list = list(scan_results)
        # print(f"Found {len(host_list)} hosts")
        return None


def result_display(res):
    output = ""
    for ip, (macs, count) in res.items():
        for mac in macs:
            output += f"""{str(mac)}\t{str(ip)}\t{count}\n"""

    return output


def passive_scan(interface_):
    print('Passive scanning on {} interface...'.format(interface_))
    sniff(filter='arp', iface=interface_, prn=passive_scan_callback)
    output = f"""
Interface: {interface_}\tMode: Passive\tFound {len(host_list)} hosts
---------------------------------------------------------------------------
MAC\t\t\tIP\t\tHost activity
---------------------------------------------------------------------------
"""
    output += result_display(scan_results)
    print(output)


def active_recon(interface_):
    ip_addr = get_if_addr(interface_)
    # packet = IP(dst=ip_addr[:ip_addr.rfind(
    #     '.')]+'.0/26', ttl=20)/ICMP()
    # packet = IP(dst='192.168.7.93-200')/ICMP()
    for ip in range(1, 255):
        dest = ip_addr[:ip_addr.rfind('.')]+'.'+str(ip)
        # print(f"checking {dest}")
        packet = IP(dst=dest, ttl=20)/ICMP()
        reply = sr1(packet, timeout=1)
        if not (reply is None):
            # print(f"{reply.src} is online")
            src_ip = reply.src
            src_mac = getmacbyip(src_ip)
            # print(src_mac)
            if src_ip in scan_results:
                scan_results[src_ip][0].add(src_mac)
                # scan_result[src_ip].extend([src_mac])
            else:
                scan_results[src_ip] = [set([src_mac]), ""]
            scan_results[src_ip][1] = ""
            host_list = list(scan_results)
            # print(f"Found {len(host_list)} hosts")
    output = f"""
Interface: {interface_}\tMode: Passive\tFound {len(host_list)} hosts
---------------------------------------------------------------------------
MAC\t\t\tIP
---------------------------------------------------------------------------
"""
    output += result_display(scan_results)
    print(output)
    return None


if __name__ == "__main__":
    if len(sys.argv) == 1:
        # show help file
        help()
    else:
        if '-p' in sys.argv or '--passive' in sys.argv:
            # Get position of -p or passive and get the next arg
            try:
                pos = sys.argv.index('--iface')
            except ValueError:
                pos = sys.argv.index('-i')
            try:
                interface_ = sys.argv[pos+1]
                # passive recon. Use sniff
                passive_scan(interface_)
            except IndexError:
                sys.exit("Please provide interface name")
        elif '-a' in sys.argv or '--active' in sys.argv:
            # Get position of -a or active and get the next arg
            try:
                pos = sys.argv.index('--iface')
            except ValueError:
                pos = sys.argv.index('-i')

            interface_ = sys.argv[pos+1]
            # passive recon. Use sniff
            active_recon(interface_)
            # try:
            #     interface_ = sys.argv[pos+1]
            #     # passive recon. Use sniff
            #     active_recon(interface_)
            # except IndexError:
            #     sys.exit("Please provide interface name")
