import os
import scapy.all as scapy
import socket
import re
import requests
import platform
import subprocess
from flask import Flask, render_template, request, jsonify
import shlex

from ping3 import ping

# Inițializează aplicația Flask
from flask_cors import CORS

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "https://wifidevices.netlify.app"}})


# Funcție pentru a obține SSID-ul curent și detalii suplimentare despre rețea
def get_wifi_details():
    try:
        if platform.system() == "Windows":
            result = subprocess.check_output(["netsh", "wlan", "show", "interfaces"], text=True, shell=True)
            details = {}
            for line in result.split("\n"):
                if "SSID" in line and "BSSID" not in line:
                    details["SSID"] = line.split(":")[1].strip()
                elif "Description" in line:
                    details["Description"] = line.split(":")[1].strip()
                elif "Band" in line:
                    details["Band"] = line.split(":")[1].strip()
                elif "Radio type" in line:
                    details["Radio Type"] = line.split(":")[1].strip()
                elif "Signal" in line:
                    details["Signal"] = line.split(":")[1].strip()
            return details
        else:
            return {"SSID": "Unknown", "Description": "Unknown", "Band": "Unknown", "Radio Type": "Unknown", "Signal": "Unknown"}
    except Exception as e:
        print(f"Could not determine network details: {e}")
        return {"SSID": "Unknown", "Description": "Unknown", "Band": "Unknown", "Radio Type": "Unknown", "Signal": "Unknown"}



# Funcție pentru a obține parolele Wi-Fi salvate pe Windows
def get_wifi_passwords():
    try:
        # Obține toate rețelele Wi-Fi salvate
        result = subprocess.check_output("netsh wlan show profile", shell=True, text=True)
        profiles = re.findall(r"(?:All User Profile\s+:\s)(.+)", result)

        wifi_passwords = []
        for wlan in profiles:
            # Escape caracterele speciale pentru netsh
            wlan_safe = wlan.replace("'", "''").replace('"', '\\"')

            # Executăm comanda pentru a obține parola rețelei
            try:
                password_result = subprocess.check_output(
                    f'netsh wlan show profile "{wlan_safe}" key=clear',
                    shell=True, text=True
                )
                password = re.search(r"Key Content\s+:\s(.+)", password_result)
                if password:
                    wifi_passwords.append({"Name": wlan, "Password": password.group(1)})
                else:
                    wifi_passwords.append({"Name": wlan, "Password": "No password set"})
            except subprocess.CalledProcessError:
                wifi_passwords.append({"Name": wlan, "Password": "Error retrieving password"})

        return wifi_passwords
    except subprocess.CalledProcessError as e:
        print(f"Error fetching Wi-Fi passwords: {e}")
        return []

# Funcție pentru a obține vendorul pe baza MAC-ului
def get_vendor(mac_address):
    try:
        response = requests.get(f"https://api.macvendors.com/{mac_address}")
        return response.text if response.status_code == 200 else "Unknown Vendor"
    except requests.exceptions.RequestException:
        return "Unknown Vendor"

# Funcție pentru a obține icoane pentru dispozitive
def get_device_icon(hostname, vendor):
    device_types = {
        "router": "fa-solid fa-wifi",
        "phone": "fa-solid fa-mobile-alt",
        "tv": "fa-solid fa-tv",
        "laptop": "fa-solid fa-laptop",
        "unknown": "fa-solid fa-question-circle",
    }

    hostname_lower = hostname.lower() if hostname else ""
    vendor_lower = vendor.lower() if vendor else ""

    if "router" in hostname_lower or "asus" in vendor_lower:
        return device_types["router"]
    elif "phone" in hostname_lower or "samsung" in vendor_lower or "iphone" in vendor_lower:
        return device_types["phone"]
    elif "tv" in hostname_lower or "samsung" in vendor_lower or "sony" in vendor_lower:
        return device_types["tv"]
    elif "laptop" in hostname_lower or "zenbook" in vendor_lower or "notebook" in vendor_lower:
        return device_types["laptop"]
    else:
        return device_types["unknown"]

# Funcție pentru a obține numele routerului din IP
def get_router_name(ip_address):
    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
        return hostname
    except socket.herror:
        return "Unknown Router"

# Funcție pentru a scana porturile deschise pentru un IP dat
def scan_ports(ip):
    open_ports = []
    common_ports = [22, 80, 443, 21, 8080, 23, 25, 3306]  # Lista de porturi comune
    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Timeout de 1 secundă pentru fiecare port
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports
# Funcție pentru a obține IP-ul gateway-ului implicit

def get_default_gateway():
    try:
        if platform.system() == "Windows":
            result = subprocess.check_output("ipconfig", text=True)
            # Căutăm linia cu 'Gateway Default' și extragem adresa IP
            match = re.search(r"Default Gateway.*: (\d+\.\d+\.\d+\.\d+)", result)
            if match:
                return match.group(1)
        elif platform.system() == "Linux":
            result = subprocess.check_output("ip route | grep default", text=True)
            # Extragem IP-ul din comanda de rutare
            match = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", result)
            if match:
                return match.group(1)
    except subprocess.CalledProcessError:
        pass
    return None

# Ruta principală a aplicației web

@app.route('/api/network-details', methods=['GET'])
def network_details():
    # Obține detaliile rețelei Wi-Fi
    wifi_details = get_wifi_details()

    # Obține IP-ul gateway-ului implicit
    gateway_ip = get_default_gateway()
    if gateway_ip:
        ip_add_range_entered = f"{gateway_ip}/24"
    else:
        ip_add_range_entered = "192.168.0.1/24"  # Dacă nu se poate obține gateway-ul, folosim valoarea default

    # Trimite cererea ARP
    result, unanswered = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip_add_range_entered), timeout=4, verbose=0)
    arp_result = result.res if result else []

    # Creează lista de dispozitive pentru a fi afișată
    devices = []
    for sent, received in arp_result:
        try:
            hostname = socket.gethostbyaddr(received.psrc)[0]
        except socket.herror:
            hostname = "Unknown"
        
        vendor = get_vendor(received.hwsrc)
        icon_class = get_device_icon(hostname, vendor)
        open_ports = scan_ports(received.psrc)  # Scanează porturile deschise

        devices.append({
            "hostname": hostname if hostname != 'Unknown' else vendor,
            "vendor": vendor if vendor != 'Unknown Vendor' else 'Unknown Vendor',
            "ip_address": received.psrc,
            "icon_class": icon_class,
            "open_ports": open_ports  # Adăugăm porturile deschise
        })

    # Obține parolele Wi-Fi salvate
    wifi_passwords = get_wifi_passwords()

    # Returnează detaliile în format JSON
    return jsonify({
        "wifi_details": wifi_details,
        "devices": devices,
        "wifi_passwords": wifi_passwords
    })

@app.route('/api/ping', methods=['GET'])
def ping_endpoint():
    ip = request.args.get('ip')
    try:
        # Rulează comanda ping în subprocess și captează rezultatul
        result = subprocess.run(
            ["ping", "-n", "4", ip],  # Ping 4 pachete
            capture_output=True,
            text=True,
            check=True
        )

        # Rezultatul comenzii ping
        output = result.stdout

        # Împărțim rezultatul pentru a extrage informațiile de interes
        output_lines = output.splitlines()

        # Extragem statisticile de ping din rezultat
        stats_line = output_lines[-3]
        stats_values = stats_line.split(", ")

        # Împărțim și extragem timpii minimi, maximi și medii
        min_time = stats_values[0].split("=")[1]
        max_time = stats_values[1].split("=")[1]
        avg_time = stats_values[2].split("=")[1]

        # Returnează rezultatul într-un format similar cu cel din cmd
        return jsonify({
            "status": "success",
            "output": output,
            "ping_statistics": {
                "min_time": min_time,
                "max_time": max_time,
                "avg_time": avg_time
            }
        })

    except subprocess.CalledProcessError as e:
        return jsonify({
            "status": "failure",
            "output": f"Ping failed: {e.stderr}"
        })
    except Exception as e:
        return jsonify({
            "status": "failure",
            "output": str(e)
        })
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))  # Folosește PORT din mediu sau 5000 implicit
    app.run(host='0.0.0.0', port=port)
