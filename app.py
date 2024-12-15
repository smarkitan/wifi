 import os
import subprocess
import json
from flask import Flask, jsonify, request
from flask_cors import CORS
import platform
import re

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "https://wifidevices.netlify.app"}})

# Funcție pentru a obține detaliile rețelei Wi-Fi
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

# Funcție pentru a obține detalii folosind nmap
def run_nmap_scan(ip_add_range_entered):
    try:
        # Comanda nmap -T4 -F pentru scanarea porturilor
        command = ["nmap", "-T4", "-F", ip_add_range_entered]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        
        # Parsează ieșirea comenzii nmap
        nmap_output = result.stdout
        devices = []

        # Extrage informațiile relevante din ieșirea nmap
        lines = nmap_output.splitlines()
        current_device = {}
        for line in lines:
            if "Nmap scan report for" in line:
                if current_device:
                    devices.append(current_device)  # Adaugă dispozitivul anterior
                match = re.search(r"Nmap scan report for (.+) \((\d+\.\d+\.\d+\.\d+)\)", line)
                if match:
                    current_device = {
                        "hostname": match.group(1),
                        "ip_address": match.group(2),
                        "vendor": None,
                        "mac_address": None,
                        "open_ports": [],
                        "OpSys": None  # Adăugăm câmpul OS
                    }
                else:
                    current_device = {
                        "hostname": None,
                        "ip_address": line.split(" ")[-1],
                        "vendor": None,
                        "mac_address": None,
                        "open_ports": [],
                        "OpSys": None  # Adăugăm câmpul OS
                    }
            elif "MAC Address:" in line:
                mac_match = re.search(r"MAC Address: (\S+) \((.+)\)", line)
                if mac_match:
                    current_device["mac_address"] = mac_match.group(1)
                    current_device["vendor"] = mac_match.group(2)
            elif " open" in line:
                port_info = line.split()
                if len(port_info) > 2:
                    current_device["open_ports"].append({
                        "port": port_info[0],
                        "service": port_info[2]
                    })
            elif "Running:" in line:
                # Extrage OS-ul din linia "Running:"
                current_device["OpSys"] = "Linux"
            elif "OS:" in line:
                current_device["OpSys"] = "Windows"

        # Adaugă ultimul dispozitiv la listă
        if current_device:
            devices.append(current_device)

        return devices
    except subprocess.CalledProcessError as e:
        return {"error": f"Failed to run nmap scan: {e.stderr}"}

# Ruta principală a aplicației web
@app.route('/api/network-details', methods=['GET'])
def network_details():
    # Obține detaliile rețelei Wi-Fi
    wifi_details = get_wifi_details()

    # Folosește IP-ul default pentru gateway
    ip_add_range_entered = "192.168.50.1/24"

    # Rulează scanarea nmap pe rețeaua locală
    devices = run_nmap_scan(ip_add_range_entered)

    # Returnează detaliile în format JSON
    return jsonify({
        "wifi_details": wifi_details,
        "devices": devices
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
    app.run(host='0.0.0.0', port=5000)
