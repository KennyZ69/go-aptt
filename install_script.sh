#!/bin/bash

# directory where the tool would be installed
INSTALL_DIR="$HOME/go-aptt"
BINARY_PATH="$INSTALL_DIR/go-aptt"

# ensure the directory and binary exist
if [[ ! -d "$INSTALL_DIR" ]] || [[ ! -f "$BINARY_PATH" ]]; then
  echo "Installation directory or go-aptt binary not found. Exiting."
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
  echo "Added go-aptt to PATH in $PROFILE_FILE"
else
  echo "go-aptt is already in PATH in $PROFILE_FILE"
fi

# Refresh the shell configuration
source "$PROFILE_FILE"
echo "Setup complete. You can now use go-aptt from any directory."
