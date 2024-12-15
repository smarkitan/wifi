import os
import json
from flask import Flask, jsonify
from flask_cors import CORS
import scapy.all as scapy
import socket  # Import pentru reverse DNS lookup
import requests  # Import pentru rezolvarea vendorului

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "https://wifidevices.netlify.app"}})

# Functie pentru a efectua o scanare ARP si a colecta detalii despre dispozitive
def arp_scan(ip_range):
    try:
        # Trimite cererea ARP
        result, unanswered = scapy.srp(
            scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip_range),
            timeout=2,
            verbose=0
        )
        arp_result = result.res if result else []

        devices = []

        for sent, received in arp_result:
            # Determina numele dispozitivului prin reverse DNS lookup
            try:
                hostname = socket.gethostbyaddr(received.psrc)[0]
            except socket.herror:
                hostname = "Unknown"

            # Determina vendorul folosind o cerere HTTP externă
            try:
                mac_address = received.hwsrc.replace(":", "")
                response = requests.get(f"https://api.macvendors.com/{mac_address}")
                vendor = response.text if response.status_code == 200 else "Unknown"
            except requests.exceptions.RequestException:
                vendor = "Unknown"

            devices.append({
                "ip_address": received.psrc,
                "mac_address": received.hwsrc,
                "device_name": hostname,
                "vendor": vendor
            })

        return devices

    except Exception as e:
        return {"error": f"Failed to perform ARP scan: {str(e)}"}

# Ruta pentru detalii despre retea
@app.route('/api/network-details', methods=['GET'])
def network_details():
    # Setează range-ul IP pentru gateway-ul implicit
    ip_add_range_entered = "192.168.50.1/24"

    # Efectuează scanarea ARP
    devices = arp_scan(ip_add_range_entered)

    # Returnează rezultatul în format JSON
    return jsonify({
        "devices": devices
    })

if __name__ == '__main__':
    # Rulează aplicația Flask pe toate interfețele disponibile
    app.run(host='0.0.0.0', port=5000)
