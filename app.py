#!/usr/bin/env python3   
import os
import scapy.all as scapy
import socket
import re
import requests
import platform
import subprocess
from flask import Flask, render_template, jsonify  # Adăugăm jsonify pentru a returna JSON

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

            # Adăugăm un print pentru a verifica datele obținute
            print(f"WiFi Details: {details}")
            return details

        else:
            return {"SSID": "Unknown", "Description": "Unknown"}
    except Exception as e:
        return {"SSID": "Unknown", "Description": str(e)}

# Funcție pentru a obține vendorul pe baza MAC-ului
def get_vendor(mac_address):
    try:
        response = requests.get(f"https://api.macvendors.com/{mac_address}", timeout=5)
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

# Funcție pentru a obține Default Gateway folosind socket
def get_default_gateway():
    try:
        ip_address = socket.gethostbyname(socket.gethostname())
        return ip_address + "/24"
    except socket.error:
        return "192.168.1.1/24"

# Ruta principală a aplicației web
@app.route('/')
def index():
    wifi_details = get_wifi_details()
    ip_add_range_entered = get_default_gateway()
    try:
        result, unanswered = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip_add_range_entered), timeout=2, verbose=0)
    except Exception as e:
        result = []

    devices = []
    for sent, received in result:
        try:
            hostname = socket.gethostbyaddr(received.psrc)[0]
        except socket.herror:
            hostname = "Unknown"

        vendor = get_vendor(received.hwsrc)
        icon_class = get_device_icon(hostname, vendor)
        devices.append({
            "hostname": hostname if hostname != "Unknown" else vendor,
            "vendor": vendor if vendor != "Unknown Vendor" else "Unknown Vendor",
            "ip_address": received.psrc,
            "icon_class": icon_class
        })

    return render_template('index.html', wifi_details=wifi_details, devices=devices)

# Adăugăm o rută pentru /api/route
@app.route('/api/route', methods=['GET'])
def api_route():
    # Aici poți adăuga orice logică dorești
    response = {
        "message": "This is the response for /api/route",
        "status": "success"
    }
    return jsonify(response)  # Returnează un răspuns JSON

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
