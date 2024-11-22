#!/bin/bash

# directory where the tool would be installed
BINARY_NAME="goapt"
INSTALL_DIR="$HOME/goapt"
BINARY_PATH="$INSTALL_DIR/$BINARY_NAME"

echo "Downloading the goapt tool..."
curl -L -o "$BINARY_NAME" "https://github.com/KennyZ69/go-aptt/goapt"

echo "If `setcap` is unavailable on your system, you can either:
1. Install it using your package manager (e.g., `sudo apt install libcap2-bin` on Ubuntu).
2. Run the tool with `sudo` for full functionality."

echo "Moving $BINARY_NAME to $INSTALL_DIR..."
sudo mv "$BINARY_NAME" "$INSTALL_DIR"

sudo chmod +x "$BINARY_PATH"

echo "Providing CAP_NET_RAW to $BINARY_NAME"
sudo setcap cap_net_raw+ep "$BINARY_PATH"

if getcap "$BINARY_PATH" | grep -q "cap_net_raw+ep"; then
  echo "$BINARY_NAME installed and configured successfully."
else 
  echo "Failed to set CAP_NET_RAW. You may need to run this tool with sudo."
fi

# ensure the directory and binary exist
if [[ ! -d "$INSTALL_DIR" ]] || [[ ! -f "$BINARY_PATH" ]]; then
  echo "Installation directory or goapt binary not found. Exiting."
  echo "You might want to check the installation, it seems that it have failed."
  exit 1
fi

USER_SHELL=$(basename "$SHELL")

case "$USER_SHELL" in 
	"bash")
		PROFILE_FILE="$HOME/.bashrc"
		;;
	"zsh")
		PROFILE_FILE="$HOME/.zshrc"
		;;
	*)
	echo "Shell not recognized. Please add the $INSTALL_DIR dir to your PATH manually."
	exit 1
	;;
esac

# add the go-aptt binary to the path so it can be ran globally as a command for the user
if ! grep -q "$INSTALL_DIR" "$PROFILE_FILE"; then
  echo "export PATH=\"$INSTALL_DIR:\$PATH\"" >> "$PROFILE_FILE"
  echo "Added goapt to PATH in $PROFILE_FILE"
else
  echo "goapt is already in PATH in $PROFILE_FILE"
fi

# Refresh the shell configuration
source "$PROFILE_FILE"
echo "Setup complete. You can now use goapt from any directory."
