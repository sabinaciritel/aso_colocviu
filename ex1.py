from scapy.all import ARP, Ether, srp

def scan_vlans(ip_range):
    """
    Scanează rețeaua specificată pentru dispozitive active și returnează o listă de IP-uri și adrese MAC.
    
    :param ip_range: Raza de IP-uri, ex: "10.11.14.0/24"
    :return: O listă de dispozitive active, fiecare reprezentat de un dicționar cu IP și MAC.
    """
    # Creează un pachet ARP
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    # Trimite pachetele și primește răspunsurile
    result = srp(packet, timeout=2, verbose=0)[0]

    # Stochează rezultatele
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

if __name__ == "__main__":
    # Specifică raza de IP-uri a VLAN-ului (exemplu: 10.11.14.0/24)
    ip_range = "10.11.14.0/24"

    print(f"Scanare VLAN în progres pentru raza IP: {ip_range}...\n")
    active_devices = scan_vlans(ip_range)

    if active_devices:
        print("Dispozitive active găsite:")
        for device in active_devices:
            print(f"IP: {device['ip']} - MAC: {device['mac']}")
    else:
        print("Nu au fost găsite dispozitive active în raza specificată.")
