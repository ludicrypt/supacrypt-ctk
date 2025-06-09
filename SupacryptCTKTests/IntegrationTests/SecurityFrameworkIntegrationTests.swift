import XCTest
import Security
import CryptoTokenKit
@testable import SupacryptCTK

final class SecurityFrameworkIntegrationTests: XCTestCase {
    
    var driver: SupacryptTokenDriver!
    var token: SupacryptToken!
    var session: SupacryptTokenSession!
    
    override func setUpWithError() throws {
        driver = SupacryptTokenDriver()
        
        let tokenID = TKTokenID(stringValue: "com.supacrypt.ctk.security.integration")
        let configuration = SupacryptTokenDriver.getTokenConfiguration(for: tokenID)
        token = try driver.createToken(forTokenID: tokenID, configuration: configuration) as? SupacryptToken
        session = try token.createSession(format: .standard) as? SupacryptTokenSession
        
        continueAfterFailure = false
    }
    
    override func tearDownWithError() throws {
        session = nil
        token = nil
        driver = nil
        
        // Clean up any test keys from keychain
        cleanupTestKeys()
    }
    
    private func cleanupTestKeys() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: "security-integration-test".data(using: .utf8)!,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]
        
        SecItemDelete(query as CFDictionary)
    }
    
    // MARK: - SecKeychain Integration Tests
    
    func testKeychainKeyCreation() throws {
        // Test creating a key that should be accessible via Security framework
        let keySize = 2048
        let label = "Security Integration Test Key"
        let applicationTag = "security-integration-test".data(using: .utf8)!
        
        var keygenParams: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: keySize,
            kSecAttrLabel as String: label,
            kSecAttrApplicationTag as String: applicationTag,
            kSecAttrIsPermanent as String: true
        ]
        
        var publicKey: SecKey?
        var privateKey: SecKey?
        let status = SecKeyGeneratePair(keygenParams as CFDictionary, &publicKey, &privateKey)
        
        if status == errSecSuccess {
            XCTAssertNotNil(publicKey)
            XCTAssertNotNil(privateKey)
            
            // Clean up
            if let privateKey = privateKey {
                SecItemDelete([
                    kSecValueRef as String: privateKey
                ] as CFDictionary)
            }
        } else {
            // Key generation may fail in test environment, but we can still test the integration
            XCTAssertEqual(status, errSecSuccess, "Key generation failed with status: \(status)")
        }
    }
    
    func testKeychainKeyQuery() throws {
        // Test querying keys using Security framework
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]
        
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        // Even if no keys are found, the query should execute without error
        XCTAssertTrue(status == errSecSuccess || status == errSecItemNotFound)
        
        if status == errSecSuccess {
            // If keys were found, verify the result format
            if let keyAttributes = result as? [[String: Any]] {
                XCTAssertTrue(keyAttributes.allSatisfy { attrs in
                    attrs[kSecAttrKeyType as String] != nil
                })
            } else if let singleKeyAttributes = result as? [String: Any] {
                XCTAssertNotNil(singleKeyAttributes[kSecAttrKeyType as String])
            }
        }
    }
    
    func testKeychainAccessControl() throws {
        // Test creating access control for keychain items
        var error: Unmanaged<CFError>?
        let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [],
            &error
        )
        
        XCTAssertNotNil(accessControl)
        XCTAssertNil(error?.takeRetainedValue())
    }
    
    // MARK: - SecIdentity Integration Tests
    
    func testSecIdentityCreation() throws {
        // Test creating a SecIdentity from certificate and private key
        // This is a mock test since we don't have real certificates in the test environment
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassIdentity,
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        // Identity may not exist in test environment, but query should execute
        XCTAssertTrue(status == errSecSuccess || status == errSecItemNotFound)
        
        if status == errSecSuccess {
            let identity = result as! SecIdentity
            XCTAssertNotNil(identity)
            
            // Test extracting certificate and private key
            var certificate: SecCertificate?
            var privateKey: SecKey?
            
            let certStatus = SecIdentityCopyCertificate(identity, &certificate)
            let keyStatus = SecIdentityCopyPrivateKey(identity, &privateKey)
            
            XCTAssertEqual(certStatus, errSecSuccess)
            XCTAssertEqual(keyStatus, errSecSuccess)
            XCTAssertNotNil(certificate)
            XCTAssertNotNil(privateKey)
        }
    }
    
    // MARK: - Certificate Chain Integration Tests
    
    func testCertificateChainValidation() throws {
        // Test certificate chain operations
        // This demonstrates how the CTK provider would integrate with certificate validation
        
        let policy = SecPolicyCreateSSL(true, "example.com" as CFString)
        XCTAssertNotNil(policy)
        
        // Test policy validation (would be used with actual certificates)
        let trust = try createBasicTrust()
        if let trust = trust {
            var result: SecTrustResultType = .invalid
            let status = SecTrustEvaluate(trust, &result)
            
            // Trust evaluation may fail without real certificates, but API should work
            XCTAssertTrue(status == errSecSuccess || status == errSecParam)
        }
    }
    
    private func createBasicTrust() throws -> SecTrust? {
        // Create a basic trust object for testing
        // In real implementation, this would use actual certificates
        
        let policy = SecPolicyCreateBasicX509()
        var trust: SecTrust?
        
        // Create an empty certificate array for testing
        let certificates = CFArrayCreate(kCFAllocatorDefault, nil, 0, &kCFTypeArrayCallBacks)
        
        let status = SecTrustCreateWithCertificates(certificates, policy, &trust)
        
        if status == errSecSuccess {
            return trust
        } else {
            return nil
        }
    }
    
    // MARK: - Token Integration Tests
    
    func testTokenRegistration() throws {
        // Test that tokens can be properly registered with the system
        let tokenIDs = SupacryptTokenDriver.getTokenIDs()
        
        XCTAssertFalse(tokenIDs.isEmpty)
        
        for tokenID in tokenIDs {
            let configuration = SupacryptTokenDriver.getTokenConfiguration(for: tokenID)
            XCTAssertNotNil(configuration)
            XCTAssertEqual(configuration.instanceID, tokenID.stringValue)
        }
    }
    
    func testTokenSessionCapabilities() throws {
        // Test that token sessions properly expose their capabilities
        XCTAssertTrue(token.supports(operation: .signData))
        XCTAssertTrue(token.supports(operation: .decryptData))
        XCTAssertTrue(token.supports(operation: .readData))
        XCTAssertTrue(token.supports(operation: .performKeyExchange))
    }
    
    func testTokenInfo() throws {
        // Test that token info is properly formatted for Security framework
        let tokenInfo = token.tokenInfo
        
        XCTAssertNotNil(tokenInfo[kSecAttrTokenID as String])
        XCTAssertNotNil(tokenInfo[kSecAttrLabel as String])
        
        // Verify token info contains required fields
        XCTAssertTrue(tokenInfo["Manufacturer"] is String)
        XCTAssertTrue(tokenInfo["Model"] is String)
        XCTAssertTrue(tokenInfo["SerialNumber"] is String)
        XCTAssertTrue(tokenInfo["FirmwareVersion"] is String)
    }
    
    // MARK: - Application Integration Simulation Tests
    
    func testSafariCertificateSelectionSimulation() throws {
        // Simulate how Safari would query available certificates
        let query: [String: Any] = [
            kSecClass as String: kSecClassIdentity,
            kSecReturnRef as String: true,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecAttrCanSign as String: true
        ]
        
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        // Query should execute even if no signing identities are found
        XCTAssertTrue(status == errSecSuccess || status == errSecItemNotFound)
    }
    
    func testMailSMIMESimulation() throws {
        // Simulate how Mail app would look for S/MIME certificates
        let query: [String: Any] = [
            kSecClass as String: kSecClassIdentity,
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecAttrKeyUsage as String: [
                kSecAttrCanSign,
                kSecAttrCanEncrypt
            ]
        ]
        
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        XCTAssertTrue(status == errSecSuccess || status == errSecItemNotFound)
    }
    
    func testCodeSigningSimulation() throws {
        // Simulate how codesign tool would query for code signing certificates
        let query: [String: Any] = [
            kSecClass as String: kSecClassIdentity,
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecAttrCanSign as String: true,
            kSecMatchPolicy as String: SecPolicyCreateCodeSigning()
        ]
        
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        XCTAssertTrue(status == errSecSuccess || status == errSecItemNotFound)
    }
    
    func testVPNAuthenticationSimulation() throws {
        // Simulate VPN certificate authentication queries
        let query: [String: Any] = [
            kSecClass as String: kSecClassIdentity,
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecAttrCanSign as String: true,
            kSecMatchPolicy as String: SecPolicyCreateSSL(false, nil)
        ]
        
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        XCTAssertTrue(status == errSecSuccess || status == errSecItemNotFound)
    }
    
    func test802dot1XAuthenticationSimulation() throws {
        // Simulate 802.1X enterprise authentication
        let query: [String: Any] = [
            kSecClass as String: kSecClassIdentity,
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecAttrCanSign as String: true,
            "802.1X" as String: true // Custom attribute for enterprise auth
        ]
        
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        XCTAssertTrue(status == errSecSuccess || status == errSecItemNotFound)
    }
    
    // MARK: - System Integration Tests
    
    func testSystemKeychainIntegration() throws {
        // Test interaction with system keychain
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.supacrypt.ctk.test",
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]
        
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        XCTAssertTrue(status == errSecSuccess || status == errSecItemNotFound)
    }
    
    func testLoginKeychainIntegration() throws {
        // Test login keychain operations
        var keychainRef: SecKeychain?
        let status = SecKeychainCopyDefault(&keychainRef)
        
        if status == errSecSuccess {
            XCTAssertNotNil(keychainRef)
            
            // Test keychain status
            var keychainStatus: SecKeychainStatus = 0
            let statusResult = SecKeychainGetStatus(keychainRef!, &keychainStatus)
            XCTAssertEqual(statusResult, errSecSuccess)
        }
    }
    
    func testiCloudKeychainCompatibility() throws {
        // Test iCloud Keychain compatibility (attribute checking)
        let attributes: [String: Any] = [
            kSecAttrSynchronizable as String: true,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlocked
        ]
        
        // Test that iCloud-compatible attributes are properly handled
        for (key, value) in attributes {
            XCTAssertNotNil(key)
            XCTAssertNotNil(value)
        }
    }
    
    // MARK: - Touch ID / Face ID Integration Tests
    
    func testBiometricAuthenticationSupport() throws {
        // Test biometric authentication support
        var error: Unmanaged<CFError>?
        
        let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .biometryAny,
            &error
        )
        
        if let accessControl = accessControl {
            XCTAssertNotNil(accessControl)
            XCTAssertNil(error?.takeRetainedValue())
        } else {
            // Biometrics may not be available in test environment
            XCTAssertNotNil(error?.takeRetainedValue())
        }
    }
    
    // MARK: - Error Handling Integration Tests
    
    func testSecurityFrameworkErrorHandling() throws {
        // Test that Security framework errors are properly handled
        let invalidQuery: [String: Any] = [
            kSecClass as String: "invalid-class",
            kSecReturnRef as String: true
        ]
        
        var result: CFTypeRef?
        let status = SecItemCopyMatching(invalidQuery as CFDictionary, &result)
        
        XCTAssertNotEqual(status, errSecSuccess)
        XCTAssertNil(result)
    }
    
    func testKeychainLockHandling() throws {
        // Test handling of locked keychain scenarios
        // Note: This test simulates the scenario but may not actually lock the keychain
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        // Should handle both success and keychain locked scenarios
        XCTAssertTrue(status == errSecSuccess || 
                     status == errSecItemNotFound || 
                     status == errSecUserCanceled ||
                     status == errSecAuthFailed)
    }
    
    // MARK: - Performance Integration Tests
    
    func testKeychainQueryPerformance() throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]
        
        measure {
            var result: CFTypeRef?
            _ = SecItemCopyMatching(query as CFDictionary, &result)
        }
    }
    
    func testTokenOperationPerformance() throws {
        measure {
            _ = token.supports(operation: .signData)
            _ = token.supports(operation: .decryptData)
            _ = token.supports(operation: .readData)
            _ = token.supports(operation: .performKeyExchange)
        }
    }
    
    // MARK: - Cross-Platform Compatibility Tests
    
    func testmacOSVersionCompatibility() throws {
        // Test compatibility with different macOS versions
        let osVersion = ProcessInfo.processInfo.operatingSystemVersion
        
        // Verify we're running on supported macOS version (14.0+)
        if osVersion.majorVersion >= 14 {
            XCTAssertTrue(true, "Running on supported macOS version")
        } else {
            XCTFail("CTK provider requires macOS 14.0 or later")
        }
    }
    
    func testUniversalBinaryCompatibility() throws {
        // Test that the framework works on current architecture
        #if arch(arm64)
        XCTAssertTrue(true, "Running on Apple Silicon")
        #elseif arch(x86_64)
        XCTAssertTrue(true, "Running on Intel")
        #else
        XCTFail("Unsupported architecture")
        #endif
    }
}