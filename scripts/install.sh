#!/bin/bash

# Supacrypt CTK Provider Installation Script
# This script installs the CTK system extension and configures it for use

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
EXTENSION_BUNDLE="$PROJECT_DIR/build/Products/SupacryptCTK.systemextension"
SYSTEM_EXTENSIONS_DIR="/Library/SystemExtensions"
INSTALL_DIR="$SYSTEM_EXTENSIONS_DIR/com.supacrypt.ctk"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        log_error "This script should not be run as root. Please run as a regular user."
        log_info "The script will request administrator privileges when needed."
        exit 1
    fi
}

# Function to check if running on macOS
check_macos() {
    if [[ "$(uname)" != "Darwin" ]]; then
        log_error "This script must be run on macOS"
        exit 1
    fi
    
    # Check macOS version
    local macos_version=$(sw_vers -productVersion)
    local major_version=$(echo "$macos_version" | cut -d '.' -f 1)
    
    if [[ $major_version -lt 14 ]]; then
        log_error "macOS 14.0 (Sonoma) or later is required. Current version: $macos_version"
        exit 1
    fi
    
    log_info "macOS version: $macos_version"
}

# Function to check if extension bundle exists
check_extension_bundle() {
    if [[ ! -d "$EXTENSION_BUNDLE" ]]; then
        log_error "Extension bundle not found at: $EXTENSION_BUNDLE"
        log_info "Please run './build.sh' first to build the extension"
        exit 1
    fi
    
    log_info "Extension bundle found: $EXTENSION_BUNDLE"
}

# Function to verify extension signature
verify_signature() {
    log_info "Verifying extension signature..."
    
    if codesign --verify --verbose "$EXTENSION_BUNDLE" 2>/dev/null; then
        log_success "Extension signature is valid"
    else
        log_warning "Extension is not signed or signature is invalid"
        log_warning "The extension may not load properly on systems with strict security settings"
        
        read -p "Do you want to continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "Installation cancelled"
            exit 1
        fi
    fi
}

# Function to request SIP status
check_sip_status() {
    log_info "Checking System Integrity Protection (SIP) status..."
    
    local sip_status=$(csrutil status)
    if echo "$sip_status" | grep -q "enabled"; then
        log_info "SIP is enabled (recommended)"
        log_warning "System extension installation may require user approval"
    else
        log_warning "SIP is disabled"
        log_info "Extension should install without additional approval"
    fi
}

# Function to stop existing extension
stop_existing_extension() {
    log_info "Checking for existing Supacrypt CTK extension..."
    
    # Check if extension is currently loaded
    if systemextensionsctl list | grep -q "com.supacrypt.ctk"; then
        log_info "Found existing extension, attempting to stop it..."
        
        # Request extension deactivation
        systemextensionsctl uninstall com.supacrypt.ctk.extension
        
        log_info "Waiting for extension to unload..."
        sleep 3
    else
        log_info "No existing extension found"
    fi
}

# Function to install extension
install_extension() {
    log_info "Installing Supacrypt CTK extension..."
    
    # Create installation directory if it doesn't exist
    sudo mkdir -p "$INSTALL_DIR"
    
    # Copy extension bundle to system location
    sudo cp -R "$EXTENSION_BUNDLE" "$INSTALL_DIR/"
    
    # Set proper permissions
    sudo chown -R root:wheel "$INSTALL_DIR/SupacryptCTK.systemextension"
    sudo chmod -R 755 "$INSTALL_DIR/SupacryptCTK.systemextension"
    
    log_success "Extension copied to system location"
    
    # Register the extension
    log_info "Registering system extension..."
    systemextensionsctl install "$INSTALL_DIR/SupacryptCTK.systemextension"
    
    if [[ $? -eq 0 ]]; then
        log_success "Extension registration initiated"
    else
        log_error "Extension registration failed"
        exit 1
    fi
}

# Function to wait for extension activation
wait_for_activation() {
    log_info "Waiting for extension to activate..."
    log_warning "You may need to approve the extension in System Preferences > Privacy & Security"
    
    local max_wait=60
    local elapsed=0
    
    while [[ $elapsed -lt $max_wait ]]; do
        if systemextensionsctl list | grep -q "com.supacrypt.ctk.*\\[activated enabled\\]"; then
            log_success "Extension activated successfully"
            return 0
        fi
        
        sleep 2
        elapsed=$((elapsed + 2))
        echo -n "."
    done
    
    echo
    log_warning "Extension activation timed out after ${max_wait} seconds"
    log_info "The extension may still be pending user approval"
    return 1
}

# Function to configure keychain access
configure_keychain() {
    log_info "Configuring keychain access..."
    
    # Create keychain access group
    if ! security list-keychains | grep -q "supacrypt"; then
        log_info "Creating Supacrypt keychain..."
        security create-keychain -p "" "supacrypt.keychain"
        security set-keychain-settings "supacrypt.keychain"
        security unlock-keychain "supacrypt.keychain"
        
        log_success "Supacrypt keychain created"
    else
        log_info "Supacrypt keychain already exists"
    fi
}

# Function to test extension
test_extension() {
    log_info "Testing extension installation..."
    
    # Check if extension is listed and active
    if systemextensionsctl list | grep -q "com.supacrypt.ctk.*\\[activated enabled\\]"; then
        log_success "Extension is active and enabled"
        
        # Test CryptoTokenKit integration
        log_info "Testing CryptoTokenKit integration..."
        
        # Use security command to list available tokens
        if security list-smartcards 2>/dev/null | grep -q "Supacrypt"; then
            log_success "Supacrypt token detected by system"
        else
            log_warning "Supacrypt token not yet detected by system"
            log_info "This is normal for a new installation - try again in a few minutes"
        fi
        
        return 0
    else
        log_error "Extension is not active"
        return 1
    fi
}

# Function to display post-installation instructions
display_instructions() {
    log_success "Installation completed!"
    echo
    log_info "Post-Installation Steps:"
    echo "  1. Open System Preferences > Privacy & Security"
    echo "  2. If prompted, allow the Supacrypt CTK extension"
    echo "  3. Restart any applications that use cryptographic tokens"
    echo "  4. Test the installation with: ./scripts/test.sh"
    echo
    log_info "Configuration Files:"
    echo "  Extension Bundle: $INSTALL_DIR/SupacryptCTK.systemextension"
    echo "  Keychain: ~/Library/Keychains/supacrypt.keychain"
    echo
    log_info "Troubleshooting:"
    echo "  - Check extension status: systemextensionsctl list"
    echo "  - View system logs: log show --predicate 'subsystem == \"com.supacrypt.ctk\"'"
    echo "  - Uninstall: ./scripts/uninstall.sh"
}

# Function to handle installation errors
handle_error() {
    log_error "Installation failed!"
    log_info "Cleaning up..."
    
    # Attempt cleanup
    if [[ -d "$INSTALL_DIR/SupacryptCTK.systemextension" ]]; then
        sudo rm -rf "$INSTALL_DIR/SupacryptCTK.systemextension"
        log_info "Cleaned up partial installation"
    fi
    
    log_info "Please check the system logs for more information:"
    log_info "log show --predicate 'subsystem == \"com.supacrypt.ctk\"' --last 5m"
    
    exit 1
}

# Main installation process
main() {
    log_info "Starting Supacrypt CTK Provider Installation"
    
    # Set error handler
    trap handle_error ERR
    
    # Pre-installation checks
    check_root
    check_macos
    check_extension_bundle
    verify_signature
    check_sip_status
    
    # Installation process
    stop_existing_extension
    install_extension
    configure_keychain
    
    # Post-installation
    if wait_for_activation; then
        test_extension
    fi
    
    display_instructions
}

# Run main function
main "$@"