![Alt text](/screenshot.png "NetCutter Screenshot")

# NetCutter

NetCutter is a GUI application built using GTK4 and Adwaita libraries in Python. It provides network scanning and ARP spoofing for network analysis and security testing.

## Features

1. **Network Scanning**:

   - Performs comprehensive network scans (both ARP and ping scans) to detect all devices on the local network.
   - Displays detected devices with IP addresses, MAC addresses, and hostnames (when available).
   - Quick refresh option for updating the device list.

2. **ARP Spoofing**:

   - Enables selective ARP spoofing on user-chosen devices.
   - Redirects target devices' traffic through the user's machine.
   - Includes a fail-safe to restore normal network state.

3. **Customization**:

   - Adjustable thread count for optimized network scanning performance.
   - "Select All" switch for bulk enabling/disabling of spoofing targets.

4. **Logging and Status Reporting**:
   - Comprehensive logging for debugging and monitoring.
   - Real-time status updates in the GUI.

## Prerequisites

- Python 3.6 or higher
- Root/Administrator privileges (required for ARP spoofing)

## Installation

1. Clone the repository:

   ```
   git clone https://github.com/youcefzaid/netcutter.git
   cd netcutter
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

1. Launch NetCutter:

   ```
   sudo python3 main.py
   ```

   Note: Root privileges are necessary for ARP spoofing functionality.

2. The application will initiate a full network scan and display detected devices.

3. Use the "Select All" switch or individual toggles to choose spoofing targets.

4. Click "Start Spoofing" to begin the ARP spoofing process.

5. Click "Stop Spoofing" to cease the attack and restore normal network operation.

6. Use the refresh button for a quick network rescan.

7. Adjust thread count in the settings menu to optimize scanning performance.

## Dependencies

NetCutter relies on the following Python libraries:

- `gi` (GTK4 and Adwaita integration)
- `scapy` (Network scanning and ARP spoofing)
- `netifaces` (Network interface detection)
- `ipaddress` (IP address manipulation)

For a complete list of dependencies, refer to the `requirements.txt` file.

## Disclaimer

NetCutter is designed for educational and ethical testing purposes only. Ensure you have explicit permission before using this tool on any network or devices you do not own or have the right to test. Unauthorized use of this tool may be illegal and is strictly prohibited.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the [GPL-3.0 License](LICENSE).

## Support

If you encounter any issues or have questions, please file an issue on the GitHub issue tracker.
