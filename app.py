#!/usr/bin/env python3
import os
import scapy.all as scapy
import socket
import requests
from flask import Flask, render_template, jsonify

# Inițializează aplicația Flask
app = Flask(__name__)

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

    # Verifică tipul dispozitivului și returnează icoana corespunzătoare
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

# Funcție pentru a obține gama de IP-uri pentru rețeaua locală
def get_ip_range():
    # Presupunem o rețea locală tipică pentru testare
    return "192.168.50.1/24"

# Ruta principală a aplicației web
@app.route('/')
def index():
    ip_add_range_entered = get_ip_range()

    try:
        # Folosim scapy pentru a trimite un ARP request către IP-urile din rețea
        result, unanswered = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip_add_range_entered), timeout=2, verbose=0)
    except Exception as e:
        result = []

    devices = []
    # Procesăm rezultatele și extragem informațiile despre fiecare dispozitiv
    for sent, received in result:
        try:
            # Încercăm să obținem numele dispozitivului (hostname)
            hostname = socket.gethostbyaddr(received.psrc)[0]
        except socket.herror:
            # Dacă nu reușim să obținem hostname-ul, îl setăm la "Unknown"
            hostname = "Unknown"

        vendor = get_vendor(received.hwsrc)  # Obținem vendorul pe baza MAC-ului
        icon_class = get_device_icon(hostname, vendor)  # Obținem icoana pentru dispozitiv

        # Adăugăm dispozitivul într-o listă cu detalii relevante
        devices.append({
            "hostname": hostname if hostname != "Unknown" else vendor,
            "vendor": vendor if vendor != "Unknown Vendor" else "Unknown Vendor",
            "ip_address": received.psrc,
            "mac_address": received.hwsrc,
            "icon_class": icon_class
        })

    # Returnăm template-ul cu lista de dispozitive
    return render_template('index.html', devices=devices)

# Adăugăm o rută API pentru /api/route
@app.route('/api/route', methods=['GET'])
def api_route():
    response = {
        "message": "This is the response for /api/route",
        "status": "success"
    }
    return jsonify(response)

# Main: Inițializăm aplicația Flask
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))  # Portul pentru serverul Flask
    app.run(host="0.0.0.0", port=port, debug=True)  # Pornim serverul Flask
