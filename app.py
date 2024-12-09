#!/usr/bin/env python3
import os
import scapy.all as scapy
import socket
import re
import requests
import platform
import subprocess
from flask import Flask, render_template

# Inițializează aplicația Flask
app = Flask(__name__)

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
    elif "phone" in hostname_lower or "samsung" in vendor_lower or "xiaomi" in vendor_lower:
        return device_types["phone"]
    elif "tv" in hostname_lower or "lg" in vendor_lower or "sony" in vendor_lower:
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

# Funcție pentru a obține Default Gateway din ipconfig
def get_default_gateway():
    try:
        # Rulează comanda ipconfig pe Windows și obține ieșirea
        result = subprocess.check_output("ifconfig", text=True, shell=True)
        # Căutăm linia care conține "Default Gateway"
        match = re.search(r"Default Gateway . . . . . . . . : (\d+\.\d+\.\d+\.\d+)", result)
        if match:
            # Returnăm gateway-ul cu sufixul "/24"
            return match.group(1) + "/24"
        else:
            return "192.168.50.1/24"  # Valoare implicită
    except subprocess.CalledProcessError:
        return "192.168.50.1/24"  # Valoare implicită în caz de eroare

# Ruta principală a aplicației web
@app.route('/')
def index():
    # Obține detaliile rețelei Wi-Fi
    wifi_details = get_wifi_details()

    # Obține gama de IP din Default Gateway
    ip_add_range_entered = get_default_gateway()

    # Trimite cererea ARP
    result, unanswered = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip_add_range_entered), timeout=2, verbose=0)
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
        devices.append({
            "hostname": hostname if hostname != 'Unknown' else vendor,
            "vendor": vendor if vendor != 'Unknown Vendor' else 'Unknown Vendor',
            "ip_address": received.psrc,
            "icon_class": icon_class
        })

    return render_template('index.html', wifi_details=wifi_details, devices=devices)

if __name__ == "__main__":
    app.run(debug=True)
