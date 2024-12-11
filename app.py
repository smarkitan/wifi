import os
import socket
import re
import requests
import platform
import subprocess
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import scapy.all as scapy
from ping3 import ping

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "https://wifidevices.netlify.app"}})

# Utility function to execute shell commands safely
def execute_command(command):
    try:
        return subprocess.check_output(command, text=True, shell=True)
    except subprocess.CalledProcessError as e:
        print(f"Error executing command '{command}': {e}")
        return ""

# Fetch Wi-Fi details
def get_wifi_details():
    try:
        if platform.system() == "Windows":
            result = execute_command(["netsh", "wlan", "show", "interfaces"])
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
            return {
                "SSID": "Unknown",
                "Description": "Unknown",
                "Band": "Unknown",
                "Radio Type": "Unknown",
                "Signal": "Unknown",
            }
    except Exception as e:
        print(f"Error fetching Wi-Fi details: {e}")
        return {
            "SSID": "Unknown",
            "Description": "Unknown",
            "Band": "Unknown",
            "Radio Type": "Unknown",
            "Signal": "Unknown",
        }

# Fetch Wi-Fi passwords
def get_wifi_passwords():
    try:
        result = execute_command("netsh wlan show profile")
        profiles = re.findall(r"(?:All User Profile\s+:\s)(.+)", result)
        
        wifi_passwords = []
        for wlan in profiles:
            wlan_safe = wlan.replace("'", "''").replace('"', '\\\"')
            password_result = execute_command(f'netsh wlan show profile "{wlan_safe}" key=clear')
            password = re.search(r"Key Content\s+:\s(.+)", password_result)
            wifi_passwords.append({
                "Name": wlan,
                "Password": password.group(1) if password else "No password set"
            })
        
        return wifi_passwords
    except Exception as e:
        print(f"Error fetching Wi-Fi passwords: {e}")
        return []

# Get vendor by MAC address
def get_vendor(mac_address):
    try:
        response = requests.get(f"https://api.macvendors.com/{mac_address}")
        return response.text if response.status_code == 200 else "Unknown Vendor"
    except requests.RequestException:
        return "Unknown Vendor"

# Determine device icon based on hostname and vendor
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

# Get router name by IP address
def get_router_name(ip_address):
    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
        return hostname
    except socket.herror:
        return "Unknown Router"

# Scan open ports on a given IP
def scan_ports(ip):
    open_ports = []
    common_ports = [22, 80, 443, 21, 8080, 23, 25, 3306]
    for port in common_ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
    return open_ports

# Get default gateway IP
def get_default_gateway():
    try:
        if platform.system() == "Windows":
            result = execute_command("ipconfig")
            match = re.search(r"Default Gateway.*: (\d+\.\d+\.\d+\.\d+)", result)
            return match.group(1) if match else None
        elif platform.system() == "Linux":
            result = execute_command("ip route | grep default")
            match = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", result)
            return match.group(1) if match else None
    except Exception as e:
        print(f"Error fetching default gateway: {e}")
    return None

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/network-details', methods=['GET'])
def network_details():
    wifi_details = get_wifi_details()
    gateway_ip = get_default_gateway()
    ip_add_range_entered = f"{gateway_ip}/24" if gateway_ip else "192.168.0.1/24"

    try:
        result, unanswered = scapy.srp(
            scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip_add_range_entered),
            timeout=4, verbose=0
        )

        devices = []
        for sent, received in result:
            hostname = get_router_name(received.psrc) or "Unknown"
            vendor = get_vendor(received.hwsrc)
            icon_class = get_device_icon(hostname, vendor)
            open_ports = scan_ports(received.psrc)

            devices.append({
                "hostname": hostname,
                "vendor": vendor,
                "ip_address": received.psrc,
                "icon_class": icon_class,
                "open_ports": open_ports
            })

        wifi_passwords = get_wifi_passwords()

        return jsonify({
            "wifi_details": wifi_details,
            "devices": devices,
            "wifi_passwords": wifi_passwords
        })

    except Exception as e:
        print(f"Error during network details fetch: {e}")
        return jsonify({"error": "Unable to fetch network details."}), 500

@app.route('/api/ping', methods=['GET'])
def ping_endpoint():
    ip = request.args.get('ip')
    try:
        result = subprocess.run(
            ["ping", "-n", "4", ip],
            capture_output=True,
            text=True,
            check=True
        )

        output_lines = result.stdout.splitlines()
        stats_line = output_lines[-3] if len(output_lines) >= 3 else ""
        stats_values = stats_line.split(", ")

        min_time = stats_values[0].split("=")[1] if len(stats_values) > 0 else "N/A"
        max_time = stats_values[1].split("=")[1] if len(stats_values) > 1 else "N/A"
        avg_time = stats_values[2].split("=")[1] if len(stats_values) > 2 else "N/A"

        return jsonify({
            "status": "success",
            "output": result.stdout,
            "ping_statistics": {
                "min_time": min_time,
                "max_time": max_time,
                "avg_time": avg_time
            }
        })

    except subprocess.CalledProcessError as e:
        return jsonify({"status": "failure", "output": f"Ping failed: {e.stderr}"}), 500
    except Exception as e:
        return jsonify({"status": "failure", "output": str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
