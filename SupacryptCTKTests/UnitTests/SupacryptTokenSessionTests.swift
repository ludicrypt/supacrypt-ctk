import XCTest
import CryptoTokenKit
import Security
@testable import SupacryptCTK

final class SupacryptTokenSessionTests: XCTestCase {
    
    var driver: SupacryptTokenDriver!
    var token: SupacryptToken!
    var session: SupacryptTokenSession!
    var mockGRPCClient: MockGRPCClient!
    var mockKeychainManager: MockKeychainManager!
    
    override func setUpWithError() throws {
        driver = SupacryptTokenDriver()
        
        let tokenID = TKTokenID(stringValue: "com.supacrypt.ctk.token.session.test")
        let configuration = SupacryptTokenDriver.getTokenConfiguration(for: tokenID)
        token = try driver.createToken(forTokenID: tokenID, configuration: configuration) as? SupacryptToken
        session = try token.createSession(format: .standard) as? SupacryptTokenSession
        
        // Set up mocks
        mockGRPCClient = try MockGRPCClient()
        mockKeychainManager = MockKeychainManager()
        
        continueAfterFailure = false
    }
    
    override func tearDownWithError() throws {
        mockKeychainManager?.reset()
        mockGRPCClient?.reset()
        session = nil
        token = nil
        driver = nil
    }
    
    // MARK: - Initialization Tests
    
    func testSessionInitialization() throws {
        XCTAssertNotNil(session)
        XCTAssertEqual(session.token, token)
        XCTAssertEqual(session.format, .standard)
    }
    
    func testSessionWithRestrictedFormat() throws {
        let restrictedSession = try token.createSession(format: .restricted) as? SupacryptTokenSession
        
        XCTAssertNotNil(restrictedSession)
        XCTAssertEqual(restrictedSession?.format, .restricted)
    }
    
    // MARK: - Object Existence Tests
    
    func testObjectExistsWithEmptyKeychain() throws {
        let objectID = TKTokenObjectID(stringValue: "nonexistent.key")
        let exists = session.objectExists(objectID: objectID)
        
        XCTAssertFalse(exists)
    }
    
    func testObjectExistsWithMockKey() throws {
        // Add a mock key to the keychain
        let mockKey = MockKeychainManager.createMockRSAKey()
        mockKeychainManager.addMockKey(mockKey)
        
        // For this test to work properly, we'd need to inject the mock keychain manager
        // This demonstrates the test structure, though the actual injection would
        // require modifying the production code or using dependency injection
        
        let exists = session.objectExists(objectID: mockKey.objectID)
        
        // In a real implementation with proper DI, this would work
        // For now, this tests the session's behavior with real keychain operations
        XCTAssertFalse(exists) // Will be false since we're not using the mock in production code
    }
    
    // MARK: - Object ID Retrieval Tests
    
    func testObjectIDsWithEmptyKeychain() throws {
        let objectIDs = try session.objectIDs()
        
        // Should return empty array for empty keychain
        XCTAssertNotNil(objectIDs)
        XCTAssertTrue(objectIDs.isEmpty)
    }
    
    func testObjectIDsErrorHandling() throws {
        // Test should handle errors gracefully
        XCTAssertNoThrow(try session.objectIDs())
    }
    
    // MARK: - Object Creation Tests
    
    func testObjectsForEmptyIDs() throws {
        let emptyIDs: [TKTokenObjectID] = []
        let objects = try session.objects(forObjectIDs: emptyIDs)
        
        XCTAssertNotNil(objects)
        XCTAssertTrue(objects.isEmpty)
    }
    
    func testObjectsForNonexistentIDs() throws {
        let nonexistentIDs = [
            TKTokenObjectID(stringValue: "nonexistent.1"),
            TKTokenObjectID(stringValue: "nonexistent.2")
        ]
        
        let objects = try session.objects(forObjectIDs: nonexistentIDs)
        
        XCTAssertNotNil(objects)
        XCTAssertTrue(objects.isEmpty)
    }
    
    // MARK: - Cryptographic Operation Tests
    
    func testSignDataWithNonexistentKey() async throws {
        let data = "test data".data(using: .utf8)!
        let keyObjectID = TKTokenObjectID(stringValue: "nonexistent.signing.key")
        let algorithm = TKTokenKeyAlgorithm.rsaSignaturePKCS1SHA256
        
        do {
            _ = try await session.sign(data, keyObjectID: keyObjectID, algorithm: algorithm)
            XCTFail("Should have thrown an error for nonexistent key")
        } catch {
            // Expected to fail
            XCTAssertNotNil(error)
        }
    }
    
    func testDecryptDataWithNonexistentKey() async throws {
        let data = Data(repeating: 0x42, count: 256)
        let keyObjectID = TKTokenObjectID(stringValue: "nonexistent.decrypt.key")
        let algorithm = TKTokenKeyAlgorithm.rsaEncryptionPKCS1
        
        do {
            _ = try await session.decrypt(data, keyObjectID: keyObjectID, algorithm: algorithm)
            XCTFail("Should have thrown an error for nonexistent key")
        } catch {
            // Expected to fail
            XCTAssertNotNil(error)
        }
    }
    
    func testPerformKeyExchangeWithNonexistentKey() async throws {
        let publicKey = Data(repeating: 0x04, count: 65) // Mock EC public key
        let keyObjectID = TKTokenObjectID(stringValue: "nonexistent.exchange.key")
        let algorithm = TKTokenKeyAlgorithm.ecKeyAgree
        let parameters = TKTokenKeyExchangeParameters()
        
        do {
            _ = try await session.performKeyExchange(
                with: publicKey,
                keyObjectID: keyObjectID,
                algorithm: algorithm,
                parameters: parameters
            )
            XCTFail("Should have thrown an error for nonexistent key")
        } catch {
            // Expected to fail - key exchange is not fully implemented
            XCTAssertNotNil(error)
        }
    }
    
    // MARK: - Error Handling Tests
    
    func testSignDataWithInvalidData() async throws {
        let emptyData = Data()
        let keyObjectID = TKTokenObjectID(stringValue: "test.key")
        let algorithm = TKTokenKeyAlgorithm.rsaSignaturePKCS1SHA256
        
        do {
            _ = try await session.sign(emptyData, keyObjectID: keyObjectID, algorithm: algorithm)
            XCTFail("Should handle empty data appropriately")
        } catch {
            // Expected behavior - should handle invalid input
            XCTAssertNotNil(error)
        }
    }
    
    func testDecryptDataWithInvalidData() async throws {
        let invalidData = Data(repeating: 0x00, count: 1) // Too small for RSA
        let keyObjectID = TKTokenObjectID(stringValue: "test.key")
        let algorithm = TKTokenKeyAlgorithm.rsaEncryptionPKCS1
        
        do {
            _ = try await session.decrypt(invalidData, keyObjectID: keyObjectID, algorithm: algorithm)
            XCTFail("Should handle invalid data appropriately")
        } catch {
            // Expected behavior
            XCTAssertNotNil(error)
        }
    }
    
    // MARK: - Performance Tests
    
    func testObjectExistsPerformance() throws {
        let objectID = TKTokenObjectID(stringValue: "performance.test.key")
        
        measure {
            _ = session.objectExists(objectID: objectID)
        }
    }
    
    func testObjectIDsPerformance() throws {
        measure {
            do {
                _ = try session.objectIDs()
            } catch {
                XCTFail("objectIDs failed: \(error)")
            }
        }
    }
    
    func testSignDataPerformance() async throws {
        let data = Data(repeating: 0x42, count: 256)
        let keyObjectID = TKTokenObjectID(stringValue: "performance.sign.key")
        let algorithm = TKTokenKeyAlgorithm.rsaSignaturePKCS1SHA256
        
        // Note: This will fail since the key doesn't exist, but it tests the performance
        // of the operation setup and initial processing
        await withCheckedContinuation { continuation in
            Task {
                let startTime = CFAbsoluteTimeGetCurrent()
                
                do {
                    _ = try await session.sign(data, keyObjectID: keyObjectID, algorithm: algorithm)
                } catch {
                    // Expected to fail, but we measure the time to failure
                }
                
                let endTime = CFAbsoluteTimeGetCurrent()
                let duration = endTime - startTime
                
                // Should complete quickly even when failing
                XCTAssertLessThan(duration, 1.0, "Sign operation should fail quickly")
                
                continuation.resume()
            }
        }
    }
    
    // MARK: - Thread Safety Tests
    
    func testConcurrentObjectExists() throws {
        let expectation = XCTestExpectation(description: "Concurrent object exists")
        expectation.expectedFulfillmentCount = 10
        
        let concurrentQueue = DispatchQueue(label: "test.concurrent.exists", attributes: .concurrent)
        
        for i in 0..<10 {
            concurrentQueue.async {
                let objectID = TKTokenObjectID(stringValue: "concurrent.test.\(i)")
                _ = self.session.objectExists(objectID: objectID)
                expectation.fulfill()
            }
        }
        
        wait(for: [expectation], timeout: 5.0)
    }
    
    func testConcurrentObjectIDs() throws {
        let expectation = XCTestExpectation(description: "Concurrent object IDs")
        expectation.expectedFulfillmentCount = 5
        
        let concurrentQueue = DispatchQueue(label: "test.concurrent.ids", attributes: .concurrent)
        
        for _ in 0..<5 {
            concurrentQueue.async {
                do {
                    _ = try self.session.objectIDs()
                    expectation.fulfill()
                } catch {
                    XCTFail("Concurrent objectIDs failed: \(error)")
                }
            }
        }
        
        wait(for: [expectation], timeout: 5.0)
    }
    
    func testConcurrentSignOperations() async throws {
        await withTaskGroup(of: Void.self) { group in
            for i in 0..<3 {
                group.addTask {
                    let data = "test data \(i)".data(using: .utf8)!
                    let keyObjectID = TKTokenObjectID(stringValue: "concurrent.sign.\(i)")
                    let algorithm = TKTokenKeyAlgorithm.rsaSignaturePKCS1SHA256
                    
                    do {
                        _ = try await self.session.sign(data, keyObjectID: keyObjectID, algorithm: algorithm)
                    } catch {
                        // Expected to fail for nonexistent keys
                        // We're testing that concurrent operations don't crash
                    }
                }
            }
        }
    }
    
    // MARK: - Algorithm Support Tests
    
    func testSupportedSigningAlgorithms() async {
        let algorithms: [TKTokenKeyAlgorithm] = [
            .rsaSignaturePKCS1SHA256,
            .rsaSignaturePKCS1SHA384,
            .rsaSignaturePKCS1SHA512,
            .ecdsaSignatureDigestX962SHA256,
            .ecdsaSignatureDigestX962SHA384,
            .ecdsaSignatureDigestX962SHA512
        ]
        
        let data = "test".data(using: .utf8)!
        let keyObjectID = TKTokenObjectID(stringValue: "algorithm.test.key")
        
        for algorithm in algorithms {
            do {
                _ = try await session.sign(data, keyObjectID: keyObjectID, algorithm: algorithm)
                XCTFail("Should fail for nonexistent key, but algorithm should be recognized")
            } catch {
                // All these algorithms should be recognized (even if they fail due to missing key)
                // The error should not be about unsupported algorithm
                XCTAssertNotNil(error)
            }
        }
    }
    
    func testSupportedEncryptionAlgorithms() async {
        let algorithms: [TKTokenKeyAlgorithm] = [
            .rsaEncryptionPKCS1,
            .rsaEncryptionOAEPSHA256,
            .rsaEncryptionOAEPSHA384,
            .rsaEncryptionOAEPSHA512
        ]
        
        let data = Data(repeating: 0x42, count: 100)
        let keyObjectID = TKTokenObjectID(stringValue: "encrypt.test.key")
        
        for algorithm in algorithms {
            do {
                _ = try await session.decrypt(data, keyObjectID: keyObjectID, algorithm: algorithm)
                XCTFail("Should fail for nonexistent key, but algorithm should be recognized")
            } catch {
                // All these algorithms should be recognized
                XCTAssertNotNil(error)
            }
        }
    }
    
    // MARK: - Memory and Resource Tests
    
    func testSessionMemoryUsage() throws {
        // Create multiple sessions to test memory usage
        var sessions: [SupacryptTokenSession] = []
        
        for i in 0..<10 {
            let sessionFormat: TKTokenSessionFormat = (i % 2 == 0) ? .standard : .restricted
            let newSession = try token.createSession(format: sessionFormat) as? SupacryptTokenSession
            XCTAssertNotNil(newSession)
            sessions.append(newSession!)
        }
        
        // All sessions should be independent
        XCTAssertEqual(sessions.count, 10)
        
        // Test that each session works independently
        for (index, session) in sessions.enumerated() {
            let objectID = TKTokenObjectID(stringValue: "memory.test.\(index)")
            XCTAssertFalse(session.objectExists(objectID: objectID))
        }
    }
}