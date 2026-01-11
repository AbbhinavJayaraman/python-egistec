#!/bin/bash

# --- CONFIGURATION ---
INSTALL_DIR="/opt/egis-driver"
SOURCE_DIR="$(pwd)"

echo "[*] Starting Installation from $SOURCE_DIR..."

# 1. Clean up old mess
echo "[*] Cleaning up old services and paths..."
sudo systemctl stop open-fprintd egis-bridge 2>/dev/null
sudo systemctl disable open-fprintd egis-bridge 2>/dev/null
sudo rm -f /usr/bin/open-fprintd /usr/bin/egis-bridge

# 2. Create Directory Structure
echo "[*] Creating /opt directory structure..."
if [ -d "$INSTALL_DIR" ]; then
    sudo rm -rf "$INSTALL_DIR"
fi
sudo mkdir -p "$INSTALL_DIR/enrolled_prints"

# 3. Copy Executables
echo "[*] Copying executables..."
sudo cp "$SOURCE_DIR/bin/open-fprintd" "$INSTALL_DIR/"
sudo cp "$SOURCE_DIR/bin/egis-bridge" "$INSTALL_DIR/"

# 4. Copy Libraries (The Packages)
echo "[*] Copying libraries..."
sudo cp -r "$SOURCE_DIR/openfprintd" "$INSTALL_DIR/"
sudo cp -r "$SOURCE_DIR/egis_driver" "$INSTALL_DIR/"

# 5. Install System Configuration Files
echo "[*] Installing System Configs (Udev, Polkit, DBus)..."

# Udev Rule (Hardware Access)
sudo cp "$SOURCE_DIR/70-egis-eh575.rules" /etc/udev/rules.d/

# DBus Config (Bus Permissions)
sudo cp "$SOURCE_DIR/io.github.uunicorn.Fprint.Device.Egis.conf" /usr/share/dbus-1/system.d/

# Polkit Policy (Permission to use fingerprint without sudo)
sudo cp "$SOURCE_DIR/net.reactivated.fprint.policy" /usr/share/polkit-1/actions/

# 6. Generate Service Files (Pointing to /opt)
echo "[*] Generating Service Files..."

# -- Manager Service --
sudo tee /etc/systemd/system/open-fprintd.service > /dev/null <<EOF
[Unit]
Description=Open Fprintd Manager (Opt Install)
After=dbus.service
Wants=dbus.service

[Service]
Type=simple
User=root
Group=root
# FORCE Python to look in /opt/egis-driver
Environment="PYTHONPATH=$INSTALL_DIR"
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 -u ./open-fprintd
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# -- Bridge Service --
sudo tee /etc/systemd/system/egis-bridge.service > /dev/null <<EOF
[Unit]
Description=Egis Fingerprint Bridge (Opt Install)
After=open-fprintd.service
Requires=open-fprintd.service

[Service]
Type=simple
User=root
Group=root
# FORCE Python to look in /opt/egis-driver
Environment="PYTHONPATH=$INSTALL_DIR"
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 -u ./egis-bridge
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

# 7. Finalize
echo "[*] Setting permissions..."
sudo chmod +x "$INSTALL_DIR/open-fprintd"
sudo chmod +x "$INSTALL_DIR/egis-bridge"
sudo chmod 700 "$INSTALL_DIR/enrolled_prints"

echo "[*] reloading udev and systemd..."
sudo udevadm control --reload-rules && sudo udevadm trigger
sudo systemctl daemon-reload
sudo systemctl enable open-fprintd egis-bridge
sudo systemctl restart open-fprintd egis-bridge

echo "[SUCCESS] Installation Complete."
echo "Your system is now using the /opt/egis-driver installation."