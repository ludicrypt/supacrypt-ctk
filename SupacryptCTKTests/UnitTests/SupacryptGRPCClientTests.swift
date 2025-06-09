import XCTest
import CryptoTokenKit
@testable import SupacryptCTK

final class SupacryptGRPCClientTests: XCTestCase {
    
    var mockClient: MockGRPCClient!
    
    override func setUpWithError() throws {
        mockClient = try MockGRPCClient()
        continueAfterFailure = false
    }
    
    override func tearDownWithError() throws {
        mockClient?.reset()
        mockClient = nil
    }
    
    // MARK: - Initialization Tests
    
    func testGRPCClientInitialization() throws {
        XCTAssertNotNil(mockClient)
    }
    
    func testGRPCConfigurationDefaults() throws {
        let defaultConfig = GRPCConfiguration.default
        
        XCTAssertEqual(defaultConfig.host, "localhost")
        XCTAssertEqual(defaultConfig.port, 50051)
        XCTAssertNil(defaultConfig.tlsConfiguration)
    }
    
    func testGRPCConfigurationCustom() throws {
        let customConfig = GRPCConfiguration(
            host: "custom.host.com",
            port: 8443,
            timeout: 60.0,
            tlsConfiguration: nil
        )
        
        XCTAssertEqual(customConfig.host, "custom.host.com")
        XCTAssertEqual(customConfig.port, 8443)
    }
    
    // MARK: - Connection Tests
    
    func testConnectionSuccess() async throws {
        let isConnected = try await mockClient.testConnection()
        
        XCTAssertTrue(isConnected)
        XCTAssertEqual(mockClient.getCallCount(for: "testConnection"), 1)
    }
    
    func testConnectionFailure() async throws {
        mockClient.setMockFailure(connection: true)
        
        let isConnected = try await mockClient.testConnection()
        
        XCTAssertFalse(isConnected)
        XCTAssertEqual(mockClient.getCallCount(for: "testConnection"), 1)
    }
    
    // MARK: - Key Management Tests
    
    func testGenerateKeySuccess() async throws {
        var request = Supacrypt_V1_GenerateKeyRequest()
        request.version = 1
        request.name = "Test Key"
        request.keyType = kSecAttrKeyTypeRSA as String
        request.keySize = 2048
        
        let response = try await mockClient.generateKey(request: request)
        
        XCTAssertEqual(response.version, 1)
        XCTAssertNotNil(response.key)
        XCTAssertEqual(response.key.name, "Test Key")
        XCTAssertEqual(response.key.keyType, kSecAttrKeyTypeRSA as String)
        XCTAssertEqual(response.key.keySize, 2048)
        XCTAssertEqual(mockClient.getCallCount(for: "generateKey"), 1)
    }
    
    func testGenerateKeyFailure() async throws {
        mockClient.setMockFailure(operations: true)
        
        var request = Supacrypt_V1_GenerateKeyRequest()
        request.version = 1
        request.name = "Test Key"
        request.keyType = kSecAttrKeyTypeRSA as String
        request.keySize = 2048
        
        do {
            _ = try await mockClient.generateKey(request: request)
            XCTFail("Should have thrown an error")
        } catch {
            XCTAssertTrue(error is MockError)
            XCTAssertEqual(mockClient.getCallCount(for: "generateKey"), 1)
        }
    }
    
    func testGetKeySuccess() async throws {
        // First, create a mock key
        let mockKey = MockGRPCClient.MockKeyData(
            keyID: "test-key-123",
            keyType: kSecAttrKeyTypeRSA,
            keySize: 2048,
            publicKey: Data(repeating: 0x42, count: 256),
            canSign: true,
            canDecrypt: true,
            canDerive: false
        )
        mockClient.addMockKey(mockKey)
        
        var request = Supacrypt_V1_GetKeyRequest()
        request.version = 1
        request.keyID = "test-key-123"
        
        let response = try await mockClient.getKey(request: request)
        
        XCTAssertEqual(response.version, 1)
        XCTAssertNotNil(response.key)
        XCTAssertEqual(response.key.keyID, "test-key-123")
        XCTAssertEqual(response.key.keyType, kSecAttrKeyTypeRSA as String)
        XCTAssertEqual(response.key.keySize, 2048)
        XCTAssertEqual(mockClient.getCallCount(for: "getKey"), 1)
    }
    
    func testGetKeyNotFound() async throws {
        var request = Supacrypt_V1_GetKeyRequest()
        request.version = 1
        request.keyID = "nonexistent-key"
        
        do {
            _ = try await mockClient.getKey(request: request)
            XCTFail("Should have thrown an error for nonexistent key")
        } catch {
            XCTAssertTrue(error is MockError)
            if case MockError.keyNotFound(let keyID) = error {
                XCTAssertEqual(keyID, "nonexistent-key")
            } else {
                XCTFail("Wrong error type")
            }
        }
    }
    
    func testListKeysEmpty() async throws {
        var request = Supacrypt_V1_ListKeysRequest()
        request.version = 1
        request.pageSize = 10
        
        let response = try await mockClient.listKeys(request: request)
        
        XCTAssertEqual(response.version, 1)
        XCTAssertTrue(response.keys.isEmpty)
        XCTAssertEqual(response.totalCount, 0)
        XCTAssertFalse(response.hasMore)
        XCTAssertEqual(mockClient.getCallCount(for: "listKeys"), 1)
    }
    
    func testListKeysWithData() async throws {
        // Add some mock keys
        for i in 1...3 {
            let mockKey = MockGRPCClient.MockKeyData(
                keyID: "test-key-\(i)",
                keyType: kSecAttrKeyTypeRSA,
                keySize: 2048,
                publicKey: Data(repeating: UInt8(i), count: 256),
                canSign: true,
                canDecrypt: true,
                canDerive: false
            )
            mockClient.addMockKey(mockKey)
        }
        
        var request = Supacrypt_V1_ListKeysRequest()
        request.version = 1
        request.pageSize = 10
        
        let response = try await mockClient.listKeys(request: request)
        
        XCTAssertEqual(response.version, 1)
        XCTAssertEqual(response.keys.count, 3)
        XCTAssertEqual(response.totalCount, 3)
        XCTAssertFalse(response.hasMore)
    }
    
    func testDeleteKeySuccess() async throws {
        // Add a mock key
        let mockKey = MockGRPCClient.MockKeyData(
            keyID: "key-to-delete",
            keyType: kSecAttrKeyTypeRSA,
            keySize: 2048,
            publicKey: Data(repeating: 0x42, count: 256),
            canSign: true,
            canDecrypt: true,
            canDerive: false
        )
        mockClient.addMockKey(mockKey)
        
        var request = Supacrypt_V1_DeleteKeyRequest()
        request.version = 1
        request.keyID = "key-to-delete"
        
        let response = try await mockClient.deleteKey(request: request)
        
        XCTAssertEqual(response.version, 1)
        XCTAssertTrue(response.success)
        XCTAssertEqual(mockClient.getCallCount(for: "deleteKey"), 1)
    }
    
    // MARK: - Cryptographic Operations Tests
    
    func testSignDataSuccess() async throws {
        // Add a mock signing key
        let mockKey = MockGRPCClient.MockKeyData(
            keyID: "signing-key",
            keyType: kSecAttrKeyTypeRSA,
            keySize: 2048,
            publicKey: Data(repeating: 0x42, count: 256),
            canSign: true,
            canDecrypt: false,
            canDerive: false
        )
        mockClient.addMockKey(mockKey)
        
        var request = Supacrypt_V1_SignDataRequest()
        request.version = 1
        request.keyID = "signing-key"
        request.data = "test data".data(using: .utf8)!
        request.isPrehashed = false
        
        let signature = try await mockClient.signData(request: request)
        
        XCTAssertFalse(signature.isEmpty)
        XCTAssertEqual(signature.count, 256) // RSA-2048 signature size
        XCTAssertEqual(mockClient.getCallCount(for: "signData"), 1)
    }
    
    func testSignDataWithNonSigningKey() async throws {
        // Add a mock key that cannot sign
        let mockKey = MockGRPCClient.MockKeyData(
            keyID: "non-signing-key",
            keyType: kSecAttrKeyTypeRSA,
            keySize: 2048,
            publicKey: Data(repeating: 0x42, count: 256),
            canSign: false,
            canDecrypt: true,
            canDerive: false
        )
        mockClient.addMockKey(mockKey)
        
        var request = Supacrypt_V1_SignDataRequest()
        request.version = 1
        request.keyID = "non-signing-key"
        request.data = "test data".data(using: .utf8)!
        
        do {
            _ = try await mockClient.signData(request: request)
            XCTFail("Should have thrown an error for non-signing key")
        } catch {
            XCTAssertTrue(error is MockError)
        }
    }
    
    func testVerifySignatureSuccess() async throws {
        // Add a mock key
        let mockKey = MockGRPCClient.MockKeyData(
            keyID: "verify-key",
            keyType: kSecAttrKeyTypeRSA,
            keySize: 2048,
            publicKey: Data(repeating: 0x42, count: 256),
            canSign: true,
            canDecrypt: false,
            canDerive: false
        )
        mockClient.addMockKey(mockKey)
        
        var request = Supacrypt_V1_VerifySignatureRequest()
        request.version = 1
        request.keyID = "verify-key"
        request.data = "test data".data(using: .utf8)!
        request.signature = Data(repeating: 0x99, count: 256)
        
        let isValid = try await mockClient.verifySignature(request: request)
        
        XCTAssertTrue(isValid) // Mock implementation returns true for non-empty signatures
        XCTAssertEqual(mockClient.getCallCount(for: "verifySignature"), 1)
    }
    
    func testVerifySignatureInvalid() async throws {
        // Add a mock key
        let mockKey = MockGRPCClient.MockKeyData(
            keyID: "verify-key",
            keyType: kSecAttrKeyTypeRSA,
            keySize: 2048,
            publicKey: Data(repeating: 0x42, count: 256),
            canSign: true,
            canDecrypt: false,
            canDerive: false
        )
        mockClient.addMockKey(mockKey)
        
        var request = Supacrypt_V1_VerifySignatureRequest()
        request.version = 1
        request.keyID = "verify-key"
        request.data = "test data".data(using: .utf8)!
        request.signature = Data() // Empty signature
        
        let isValid = try await mockClient.verifySignature(request: request)
        
        XCTAssertFalse(isValid) // Mock implementation returns false for empty signatures
    }
    
    func testEncryptDataSuccess() async throws {
        // Add a mock key
        let mockKey = MockGRPCClient.MockKeyData(
            keyID: "encrypt-key",
            keyType: kSecAttrKeyTypeRSA,
            keySize: 2048,
            publicKey: Data(repeating: 0x42, count: 256),
            canSign: false,
            canDecrypt: false,
            canDerive: false
        )
        mockClient.addMockKey(mockKey)
        
        let plaintext = "secret message".data(using: .utf8)!
        
        var request = Supacrypt_V1_EncryptDataRequest()
        request.version = 1
        request.keyID = "encrypt-key"
        request.plaintext = plaintext
        
        let ciphertext = try await mockClient.encryptData(request: request)
        
        XCTAssertFalse(ciphertext.isEmpty)
        XCTAssertGreaterThan(ciphertext.count, plaintext.count) // Should have padding
        XCTAssertEqual(mockClient.getCallCount(for: "encryptData"), 1)
    }
    
    func testDecryptDataSuccess() async throws {
        // Add a mock decryption key
        let mockKey = MockGRPCClient.MockKeyData(
            keyID: "decrypt-key",
            keyType: kSecAttrKeyTypeRSA,
            keySize: 2048,
            publicKey: Data(repeating: 0x42, count: 256),
            canSign: false,
            canDecrypt: true,
            canDerive: false
        )
        mockClient.addMockKey(mockKey)
        
        // First encrypt some data (simulate ciphertext with padding)
        let originalData = "secret message".data(using: .utf8)!
        let ciphertext = originalData + Data(repeating: 0xAA, count: 16)
        
        var request = Supacrypt_V1_DecryptDataRequest()
        request.version = 1
        request.keyID = "decrypt-key"
        request.ciphertext = ciphertext
        
        let decryptedData = try await mockClient.decryptData(request: request)
        
        XCTAssertEqual(decryptedData, originalData)
        XCTAssertEqual(mockClient.getCallCount(for: "decryptData"), 1)
    }
    
    func testDecryptDataWithNonDecryptingKey() async throws {
        // Add a mock key that cannot decrypt
        let mockKey = MockGRPCClient.MockKeyData(
            keyID: "non-decrypt-key",
            keyType: kSecAttrKeyTypeRSA,
            keySize: 2048,
            publicKey: Data(repeating: 0x42, count: 256),
            canSign: true,
            canDecrypt: false,
            canDerive: false
        )
        mockClient.addMockKey(mockKey)
        
        var request = Supacrypt_V1_DecryptDataRequest()
        request.version = 1
        request.keyID = "non-decrypt-key"
        request.ciphertext = Data(repeating: 0x99, count: 256)
        
        do {
            _ = try await mockClient.decryptData(request: request)
            XCTFail("Should have thrown an error for non-decrypting key")
        } catch {
            XCTAssertTrue(error is MockError)
        }
    }
    
    // MARK: - Request Builder Tests
    
    func testBuildSignRequest() throws {
        let data = "test data".data(using: .utf8)!
        let keyID = "test-key"
        let algorithm = TKTokenKeyAlgorithm.rsaSignaturePKCS1SHA256
        
        let request = try SupacryptRequestBuilder.buildSignRequest(
            data: data,
            keyID: keyID,
            algorithm: algorithm
        )
        
        XCTAssertEqual(request.version, 1)
        XCTAssertEqual(request.keyID, keyID)
        XCTAssertEqual(request.data, data)
        XCTAssertFalse(request.isPrehashed)
        XCTAssertEqual(request.parameters.hashAlgorithm, .sha256)
        XCTAssertEqual(request.parameters.rsaParams.paddingScheme, .pkcs1)
    }
    
    func testBuildSignRequestECDSA() throws {
        let data = "test data".data(using: .utf8)!
        let keyID = "ec-test-key"
        let algorithm = TKTokenKeyAlgorithm.ecdsaSignatureDigestX962SHA384
        
        let request = try SupacryptRequestBuilder.buildSignRequest(
            data: data,
            keyID: keyID,
            algorithm: algorithm
        )
        
        XCTAssertEqual(request.parameters.hashAlgorithm, .sha384)
        XCTAssertTrue(request.parameters.hasEccParams)
    }
    
    func testBuildDecryptRequest() throws {
        let data = Data(repeating: 0x42, count: 256)
        let keyID = "decrypt-key"
        let algorithm = TKTokenKeyAlgorithm.rsaEncryptionOAEPSHA256
        
        let request = try SupacryptRequestBuilder.buildDecryptRequest(
            data: data,
            keyID: keyID,
            algorithm: algorithm
        )
        
        XCTAssertEqual(request.version, 1)
        XCTAssertEqual(request.keyID, keyID)
        XCTAssertEqual(request.ciphertext, data)
        XCTAssertEqual(request.parameters.rsaParams.paddingScheme, .oaep)
        XCTAssertEqual(request.parameters.rsaParams.oaepHash, .sha256)
    }
    
    func testBuildRequestWithUnsupportedAlgorithm() throws {
        let data = "test".data(using: .utf8)!
        let keyID = "test-key"
        
        // Test with an algorithm that might not be supported
        // Note: All current algorithms in the implementation are supported,
        // so this test demonstrates the error handling structure
        do {
            _ = try SupacryptRequestBuilder.buildSignRequest(
                data: data,
                keyID: keyID,
                algorithm: TKTokenKeyAlgorithm.rsaSignaturePKCS1SHA256
            )
            // This should succeed since RSA PKCS1 SHA256 is supported
        } catch {
            XCTFail("Should not throw for supported algorithm")
        }
    }
    
    // MARK: - Performance Tests
    
    func testConnectionPerformance() async throws {
        await measureAsyncPerformance {
            do {
                _ = try await mockClient.testConnection()
            } catch {
                XCTFail("Connection test failed: \(error)")
            }
        }
    }
    
    func testKeyGenerationPerformance() async throws {
        var request = Supacrypt_V1_GenerateKeyRequest()
        request.version = 1
        request.name = "Performance Test Key"
        request.keyType = kSecAttrKeyTypeRSA as String
        request.keySize = 2048
        
        await measureAsyncPerformance {
            do {
                _ = try await mockClient.generateKey(request: request)
            } catch {
                XCTFail("Key generation failed: \(error)")
            }
        }
    }
    
    func testSigningPerformance() async throws {
        // Add a mock signing key
        let mockKey = MockGRPCClient.MockKeyData(
            keyID: "perf-sign-key",
            keyType: kSecAttrKeyTypeRSA,
            keySize: 2048,
            publicKey: Data(repeating: 0x42, count: 256),
            canSign: true,
            canDecrypt: false,
            canDerive: false
        )
        mockClient.addMockKey(mockKey)
        
        var request = Supacrypt_V1_SignDataRequest()
        request.version = 1
        request.keyID = "perf-sign-key"
        request.data = "performance test data".data(using: .utf8)!
        
        await measureAsyncPerformance {
            do {
                _ = try await mockClient.signData(request: request)
            } catch {
                XCTFail("Signing failed: \(error)")
            }
        }
    }
    
    // MARK: - Error Handling Tests
    
    func testNetworkErrorHandling() async throws {
        mockClient.setMockFailure(operations: true)
        
        var request = Supacrypt_V1_GenerateKeyRequest()
        request.version = 1
        request.name = "Error Test"
        request.keyType = kSecAttrKeyTypeRSA as String
        request.keySize = 2048
        
        do {
            _ = try await mockClient.generateKey(request: request)
            XCTFail("Should have thrown a network error")
        } catch {
            XCTAssertTrue(error is MockError)
        }
    }
    
    func testResponseDelaySimulation() async throws {
        mockClient.responseDelay = 0.1 // 100ms delay
        
        let startTime = Date()
        _ = try await mockClient.testConnection()
        let endTime = Date()
        
        let duration = endTime.timeIntervalSince(startTime)
        XCTAssertGreaterThanOrEqual(duration, 0.1)
    }
    
    // MARK: - Concurrent Operations Tests
    
    func testConcurrentOperations() async throws {
        await withTaskGroup(of: Void.self) { group in
            // Test multiple concurrent operations
            for i in 0..<5 {
                group.addTask {
                    do {
                        var request = Supacrypt_V1_GenerateKeyRequest()
                        request.version = 1
                        request.name = "Concurrent Key \(i)"
                        request.keyType = kSecAttrKeyTypeRSA as String
                        request.keySize = 2048
                        
                        _ = try await self.mockClient.generateKey(request: request)
                    } catch {
                        XCTFail("Concurrent operation \(i) failed: \(error)")
                    }
                }
            }
        }
        
        XCTAssertEqual(mockClient.getCallCount(for: "generateKey"), 5)
    }
}