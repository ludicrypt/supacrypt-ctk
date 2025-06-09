#!/bin/bash

# Supacrypt CTK Universal Binary Build Script
# This script builds the CTK provider as a Universal Binary for both Apple Silicon and Intel

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR"
BUILD_DIR="$PROJECT_DIR/build"
PRODUCTS_DIR="$BUILD_DIR/Products"

# Build configuration
CONFIGURATION="${CONFIGURATION:-Release}"
SCHEME_NAME="SupacryptCTK"

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

# Function to check if running on macOS
check_macos() {
    if [[ "$(uname)" != "Darwin" ]]; then
        log_error "This script must be run on macOS"
        exit 1
    fi
}

# Function to check Xcode installation
check_xcode() {
    if ! command -v xcodebuild &> /dev/null; then
        log_error "Xcode command line tools not found. Please install Xcode."
        exit 1
    fi
    
    local xcode_version=$(xcodebuild -version | head -n 1 | cut -d ' ' -f 2)
    log_info "Using Xcode version: $xcode_version"
}

# Function to clean build directory
clean_build() {
    log_info "Cleaning build directory..."
    rm -rf "$BUILD_DIR"
    mkdir -p "$BUILD_DIR"
    mkdir -p "$PRODUCTS_DIR"
}

# Function to build for specific architecture
build_architecture() {
    local arch=$1
    local arch_build_dir="$BUILD_DIR/$arch"
    
    log_info "Building for architecture: $arch"
    
    # Set architecture-specific settings
    local arch_settings=""
    if [[ "$arch" == "arm64" ]]; then
        arch_settings="ARCHS=arm64 VALID_ARCHS=arm64"
    elif [[ "$arch" == "x86_64" ]]; then
        arch_settings="ARCHS=x86_64 VALID_ARCHS=x86_64"
    fi
    
    # Build using Swift Package Manager
    swift build \
        --configuration release \
        --arch "$arch" \
        --build-path "$arch_build_dir" \
        --product SupacryptCTK
    
    if [[ $? -eq 0 ]]; then
        log_success "Successfully built for $arch"
    else
        log_error "Failed to build for $arch"
        exit 1
    fi
}

# Function to create universal binary
create_universal_binary() {
    log_info "Creating Universal Binary..."
    
    local arm64_binary="$BUILD_DIR/arm64/release/SupacryptCTK"
    local x86_64_binary="$BUILD_DIR/x86_64/release/SupacryptCTK"
    local universal_binary="$PRODUCTS_DIR/SupacryptCTK"
    
    # Check if both architecture binaries exist
    if [[ ! -f "$arm64_binary" ]]; then
        log_error "ARM64 binary not found at: $arm64_binary"
        exit 1
    fi
    
    if [[ ! -f "$x86_64_binary" ]]; then
        log_error "x86_64 binary not found at: $x86_64_binary"
        exit 1
    fi
    
    # Create universal binary using lipo
    lipo -create "$arm64_binary" "$x86_64_binary" -output "$universal_binary"
    
    if [[ $? -eq 0 ]]; then
        log_success "Universal binary created at: $universal_binary"
    else
        log_error "Failed to create universal binary"
        exit 1
    fi
    
    # Verify the universal binary
    log_info "Verifying universal binary..."
    lipo -info "$universal_binary"
    file "$universal_binary"
}

# Function to create system extension bundle
create_extension_bundle() {
    log_info "Creating system extension bundle..."
    
    local bundle_dir="$PRODUCTS_DIR/SupacryptCTK.systemextension"
    local contents_dir="$bundle_dir/Contents"
    local macos_dir="$contents_dir/MacOS"
    local resources_dir="$contents_dir/Resources"
    
    # Create bundle directory structure
    mkdir -p "$macos_dir"
    mkdir -p "$resources_dir"
    
    # Copy the universal binary
    cp "$PRODUCTS_DIR/SupacryptCTK" "$macos_dir/"
    
    # Create Info.plist
    cat > "$contents_dir/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleDisplayName</key>
    <string>Supacrypt CTK Provider</string>
    <key>CFBundleExecutable</key>
    <string>SupacryptCTK</string>
    <key>CFBundleIdentifier</key>
    <string>com.supacrypt.ctk.extension</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>SupacryptCTK</string>
    <key>CFBundlePackageType</key>
    <string>XPC!</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>LSMinimumSystemVersion</key>
    <string>14.0</string>
    <key>NSExtension</key>
    <dict>
        <key>NSExtensionPointIdentifier</key>
        <string>com.apple.ctk.token-driver</string>
        <key>NSExtensionPrincipalClass</key>
        <string>SupacryptTokenDriver</string>
    </dict>
    <key>NSSupportsAutomaticTermination</key>
    <true/>
</dict>
</plist>
EOF
    
    log_success "System extension bundle created at: $bundle_dir"
}

# Function to sign the extension (if certificates are available)
sign_extension() {
    local bundle_dir="$PRODUCTS_DIR/SupacryptCTK.systemextension"
    
    # Check if signing identity is available
    if security find-identity -v -p codesigning | grep -q "Developer ID Application"; then
        log_info "Code signing the extension..."
        
        # Sign the extension
        codesign --force --sign "Developer ID Application" \
                 --entitlements "$PROJECT_DIR/entitlements.plist" \
                 --options runtime \
                 "$bundle_dir"
        
        if [[ $? -eq 0 ]]; then
            log_success "Extension signed successfully"
            
            # Verify signature
            codesign --verify --verbose "$bundle_dir"
        else
            log_warning "Code signing failed - extension will not be signed"
        fi
    else
        log_warning "No valid signing identity found - extension will not be signed"
    fi
}

# Function to create entitlements file
create_entitlements() {
    log_info "Creating entitlements file..."
    
    cat > "$PROJECT_DIR/entitlements.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.app-sandbox</key>
    <true/>
    <key>com.apple.security.application-groups</key>
    <array>
        <string>com.supacrypt.ctk</string>
    </array>
    <key>keychain-access-groups</key>
    <array>
        <string>com.supacrypt.ctk</string>
    </array>
    <key>com.apple.security.network.client</key>
    <true/>
    <key>com.apple.security.cryptokit.operation</key>
    <true/>
</dict>
</plist>
EOF
    
    log_success "Entitlements file created"
}

# Function to display build summary
display_summary() {
    log_success "Build completed successfully!"
    echo
    log_info "Build Summary:"
    echo "  Configuration: $CONFIGURATION"
    echo "  Architecture: Universal (arm64 + x86_64)"
    echo "  Output Directory: $PRODUCTS_DIR"
    echo "  Extension Bundle: $PRODUCTS_DIR/SupacryptCTK.systemextension"
    echo
    log_info "Next Steps:"
    echo "  1. Install the system extension using the installer script"
    echo "  2. Enable the extension in System Preferences > Privacy & Security"
    echo "  3. Test the CTK provider with supported applications"
}

# Main build process
main() {
    log_info "Starting Supacrypt CTK Universal Binary Build"
    
    # Pre-build checks
    check_macos
    check_xcode
    
    # Build process
    clean_build
    create_entitlements
    
    # Build for both architectures
    build_architecture "arm64"
    build_architecture "x86_64"
    
    # Create universal binary and extension bundle
    create_universal_binary
    create_extension_bundle
    sign_extension
    
    # Display summary
    display_summary
}

# Run main function
main "$@"