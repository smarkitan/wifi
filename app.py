from flask import Flask, jsonify
from flask_cors import CORS
from scapy.all import ARP, Ether, srp

app = Flask(__name__)

# Configurare CORS pentru Netlify
CORS(app, resources={r"/*": {"origins": "https://wifidevices.netlify.app"}})

def scan_network(network_ip):
    """
    Scanează rețeaua și returnează o listă de dispozitive cu IP și MAC.
    :param network_ip: Adresa IP a rețelei, ex: '192.168.50.1/24'
    :return: O listă de dispozitive ({'ip': IP, 'mac': MAC}).
    """
    devices = []

    # Creăm un pachet ARP pentru scanare
    arp_request = ARP(pdst=network_ip)
    ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether_frame / arp_request

    # Trimitem pachetul și capturăm răspunsurile
    answered, _ = srp(packet, timeout=2, verbose=False)

    for sent, received in answered:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

@app.route('/api/network-details', methods=['GET'])
def network_details():
    """
    Endpoint care scanează rețeaua și returnează IP-urile și MAC-urile dispozitivelor în format JSON.
    """
    # Adresa rețelei de scanat
    ip_add_range_entered = "192.168.50.1/24"

    # Rulează scanarea rețelei
    devices = scan_network(ip_add_range_entered)

    # Returnează rezultatele în format JSON
    return jsonify({
        "devices": devices
    })
@app.route('/')
def home():
    return "Aplicația este live!"


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
