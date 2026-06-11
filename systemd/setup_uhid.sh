# Load UHID module
sudo modprobe uhid

# Configure UHID to load at boot
echo 'uhid' | sudo tee /etc/modules-load.d/uhid.conf

# Create uhid group (if it doesn't exist)
sudo groupadd uhid 2>/dev/null || true

# Add your user to uhid group
sudo usermod -aG uhid $USER

# Set up udev rules for /dev/uhid permissions
echo 'KERNEL=="uhid", GROUP="uhid", MODE="0660"' | sudo tee /etc/udev/rules.d/10-uhid.rules

# Reload udev rules
sudo udevadm control --reload-rules
sudo udevadm trigger