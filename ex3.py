import nmap

def scan_services(ip):
    """
    Scanează serviciile expuse de o mașină specificată prin IP.
    
    :param ip: Adresa IP a mașinii de scanat
    :return: O listă cu detalii despre serviciile descoperite (port, nume, versiune)
    """
    nm = nmap.PortScanner()
    try:
        print(f"Scanare servicii expuse pe {ip}...")
        # Scanăm pentru toate porturile deschise și identificăm versiunile serviciilor
        nm.scan(ip, '1-65535', '-sV')

        # Procesăm rezultatele
        services = []
        for port in nm[ip]['tcp']:
            service = nm[ip]['tcp'][port]
            services.append({
                'port': port,
                'name': service['name'],
                'version': service.get('version', 'Unknown')
            })

        return services
    except Exception as e:
        print(f"Eroare la scanare: {e}")
        return []

if __name__ == "__main__":
    # Specificăm adresa IP a mașinii pe care dorim să o scanăm
    ip = "10.11.14.6"  # Înlocuiește cu adresa IP corespunzătoare

    # Scanăm și afișăm rezultatele
    services = scan_services(ip)
    if services:
        print("\nServicii găsite:")
        for service in services:
            print(f"Port: {service['port']} - Nume: {service['name']} - Versiune: {service['version']}")
    else:
        print("\nNu au fost găsite servicii expuse pe această mașină.")
