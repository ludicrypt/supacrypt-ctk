#!/bin/bash

# Supacrypt CTK Provider Uninstallation Script
# This script removes the CTK system extension and cleans up associated files

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
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

# Function to confirm uninstallation
confirm_uninstall() {
    echo
    log_warning "This will completely remove the Supacrypt CTK Provider from your system."
    log_warning "All stored keys and configuration will be deleted."
    echo
    read -p "Are you sure you want to continue? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Uninstallation cancelled"
        exit 0
    fi
}

# Function to stop and uninstall extension
uninstall_extension() {
    log_info "Checking for active Supacrypt CTK extension..."
    
    # Check if extension is currently loaded
    if systemextensionsctl list | grep -q "com.supacrypt.ctk"; then
        log_info "Found active extension, uninstalling..."
        
        # Uninstall the extension
        systemextensionsctl uninstall com.supacrypt.ctk.extension
        
        if [[ $? -eq 0 ]]; then
            log_success "Extension uninstallation initiated"
            
            # Wait for uninstallation to complete
            log_info "Waiting for extension to unload..."
            local max_wait=30
            local elapsed=0
            
            while [[ $elapsed -lt $max_wait ]]; do
                if ! systemextensionsctl list | grep -q "com.supacrypt.ctk"; then
                    log_success "Extension unloaded successfully"
                    break
                fi
                
                sleep 2
                elapsed=$((elapsed + 2))
                echo -n "."
            done
            
            if [[ $elapsed -ge $max_wait ]]; then
                echo
                log_warning "Extension unload timed out - continuing anyway"
            fi
        else
            log_warning "Extension uninstallation failed, but continuing cleanup"
        fi
    else
        log_info "No active extension found"
    fi
}

# Function to remove extension files
remove_extension_files() {
    log_info "Removing extension files..."
    
    # Remove extension bundle from system location
    if [[ -d "$INSTALL_DIR" ]]; then
        sudo rm -rf "$INSTALL_DIR"
        log_success "Extension files removed from $INSTALL_DIR"
    else
        log_info "No extension files found in system location"
    fi
    
    # Remove any cached extension files
    local cache_dir="/var/db/SystemExtensions"
    if [[ -d "$cache_dir" ]]; then
        sudo find "$cache_dir" -name "*supacrypt*" -type f -delete 2>/dev/null || true
        log_info "Cleared extension cache files"
    fi
}

# Function to clean up keychain
cleanup_keychain() {
    log_info "Cleaning up keychain data..."
    
    # Remove Supacrypt keychain if it exists
    if security list-keychains | grep -q "supacrypt"; then
        log_info "Removing Supacrypt keychain..."
        security delete-keychain "supacrypt.keychain" 2>/dev/null || true
        log_success "Supacrypt keychain removed"
    fi
    
    # Remove Supacrypt keys from login keychain
    log_info "Removing Supacrypt keys from login keychain..."
    
    # Find and delete all Supacrypt-related keychain items
    security find-generic-password -s "supacrypt" -D "application password" -a "com.supacrypt.ctk" -g 2>/dev/null && \
    security delete-generic-password -s "supacrypt" -D "application password" -a "com.supacrypt.ctk" 2>/dev/null || true
    
    # Remove keys with Supacrypt application tag
    local temp_query_file=$(mktemp)
    cat > "$temp_query_file" << 'EOF'
#!/usr/bin/osascript
tell application "Keychain Access"
    set keychain_items to every keychain item whose name contains "supacrypt" or comment contains "supacrypt"
    repeat with item in keychain_items
        delete item
    end repeat
end tell
EOF
    
    # Attempt to run the cleanup script
    osascript "$temp_query_file" 2>/dev/null || log_info "Manual keychain cleanup completed"
    rm -f "$temp_query_file"
    
    log_success "Keychain cleanup completed"
}

# Function to reset CryptoTokenKit cache
reset_ctk_cache() {
    log_info "Resetting CryptoTokenKit cache..."
    
    # Stop tokendriven daemon
    sudo launchctl unload /System/Library/LaunchDaemons/com.apple.security.tokendriven.plist 2>/dev/null || true
    
    # Clear CTK cache files
    sudo rm -rf /var/db/TokenAgent* 2>/dev/null || true
    sudo rm -rf /Library/Caches/com.apple.security.TokenAgent* 2>/dev/null || true
    
    # Restart tokendriven daemon
    sudo launchctl load /System/Library/LaunchDaemons/com.apple.security.tokendriven.plist 2>/dev/null || true
    
    log_success "CryptoTokenKit cache reset"
}

# Function to clean up build artifacts
cleanup_build_artifacts() {
    log_info "Cleaning up build artifacts..."
    
    local build_dir="$PROJECT_DIR/build"
    if [[ -d "$build_dir" ]]; then
        rm -rf "$build_dir"
        log_success "Build artifacts removed"
    fi
    
    # Remove entitlements file if it exists
    if [[ -f "$PROJECT_DIR/entitlements.plist" ]]; then
        rm -f "$PROJECT_DIR/entitlements.plist"
        log_info "Entitlements file removed"
    fi
}

# Function to verify complete removal
verify_removal() {
    log_info "Verifying complete removal..."
    
    local issues_found=false
    
    # Check for remaining extension
    if systemextensionsctl list | grep -q "com.supacrypt.ctk"; then
        log_warning "Extension still appears in system list"
        issues_found=true
    fi
    
    # Check for remaining files
    if [[ -d "$INSTALL_DIR" ]]; then
        log_warning "Extension files still present in $INSTALL_DIR"
        issues_found=true
    fi
    
    # Check for remaining keychain
    if security list-keychains | grep -q "supacrypt"; then
        log_warning "Supacrypt keychain still present"
        issues_found=true
    fi
    
    if [[ "$issues_found" == "false" ]]; then
        log_success "Complete removal verified"
    else
        log_warning "Some components may still be present"
        log_info "A system restart may be required to complete the removal"
    fi
}

# Function to display post-uninstall information
display_completion() {
    log_success "Uninstallation completed!"
    echo
    log_info "What was removed:"
    echo "  ✓ Supacrypt CTK system extension"
    echo "  ✓ Extension files from $INSTALL_DIR"
    echo "  ✓ Supacrypt keychain and keys"
    echo "  ✓ CryptoTokenKit cache files"
    echo "  ✓ Build artifacts"
    echo
    log_info "Recommended next steps:"
    echo "  1. Restart your system to ensure complete cleanup"
    echo "  2. Check System Preferences > Privacy & Security to verify removal"
    echo "  3. Restart any applications that were using the CTK provider"
    echo
    log_info "If you experience any issues after uninstallation:"
    echo "  - Check system logs: log show --predicate 'subsystem == \"com.supacrypt.ctk\"'"
    echo "  - Contact support if problems persist"
}

# Function to handle uninstallation errors
handle_error() {
    log_error "Uninstallation encountered an error!"
    log_warning "Some components may not have been fully removed"
    log_info "Please check the system logs for more information:"
    log_info "log show --predicate 'subsystem == \"com.supacrypt.ctk\"' --last 5m"
    echo
    log_info "You may need to:"
    echo "  1. Restart your system"
    echo "  2. Manually check System Preferences > Privacy & Security"
    echo "  3. Run this script again after restart"
    
    exit 1
}

# Main uninstallation process
main() {
    log_info "Starting Supacrypt CTK Provider Uninstallation"
    
    # Set error handler
    trap handle_error ERR
    
    # Pre-uninstallation checks
    check_root
    confirm_uninstall
    
    # Uninstallation process
    uninstall_extension
    remove_extension_files
    cleanup_keychain
    reset_ctk_cache
    cleanup_build_artifacts
    
    # Post-uninstallation
    verify_removal
    display_completion
}

# Run main function
main "$@"