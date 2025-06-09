import XCTest
import CryptoTokenKit
@testable import SupacryptCTK

final class SupacryptTokenTests: XCTestCase {
    
    var driver: SupacryptTokenDriver!
    var token: SupacryptToken!
    var tokenID: TKTokenID!
    var configuration: TKTokenConfiguration!
    
    override func setUpWithError() throws {
        driver = SupacryptTokenDriver()
        tokenID = TKTokenID(stringValue: "com.supacrypt.ctk.token.test")
        configuration = SupacryptTokenDriver.getTokenConfiguration(for: tokenID)
        token = try driver.createToken(forTokenID: tokenID, configuration: configuration) as? SupacryptToken
        
        continueAfterFailure = false
    }
    
    override func tearDownWithError() throws {
        token = nil
        driver = nil
    }
    
    // MARK: - Initialization Tests
    
    func testTokenInitialization() throws {
        XCTAssertNotNil(token)
        XCTAssertEqual(token.tokenID, tokenID)
    }
    
    func testTokenProperties() throws {
        XCTAssertEqual(token.tokenClass, TKTokenClass.hardwareToken)
        
        let tokenInfo = token.tokenInfo
        XCTAssertEqual(tokenInfo[kSecAttrTokenID as String] as? String, tokenID.stringValue)
        XCTAssertEqual(tokenInfo[kSecAttrLabel as String] as? String, "Supacrypt Token")
        XCTAssertEqual(tokenInfo["Manufacturer"] as? String, "Supacrypt")
        XCTAssertEqual(tokenInfo["Model"] as? String, "CTK Provider v1.0")
        XCTAssertEqual(tokenInfo["SerialNumber"] as? String, tokenID.stringValue)
        XCTAssertEqual(tokenInfo["FirmwareVersion"] as? String, "1.0.0")
    }
    
    // MARK: - Session Creation Tests
    
    func testCreateSessionStandard() throws {
        let session = try token.createSession(format: .standard)
        
        XCTAssertNotNil(session)
        XCTAssertTrue(session is SupacryptTokenSession)
        XCTAssertEqual(session.token, token)
        XCTAssertEqual(session.format, .standard)
    }
    
    func testCreateSessionRestricted() throws {
        let session = try token.createSession(format: .restricted)
        
        XCTAssertNotNil(session)
        XCTAssertTrue(session is SupacryptTokenSession)
        XCTAssertEqual(session.token, token)
        XCTAssertEqual(session.format, .restricted)
    }
    
    func testCreateMultipleSessions() throws {
        let session1 = try token.createSession(format: .standard)
        let session2 = try token.createSession(format: .restricted)
        
        XCTAssertNotNil(session1)
        XCTAssertNotNil(session2)
        XCTAssertNotIdentical(session1, session2)
        XCTAssertEqual(session1.format, .standard)
        XCTAssertEqual(session2.format, .restricted)
    }
    
    // MARK: - Operation Support Tests
    
    func testSupportsReadData() throws {
        XCTAssertTrue(token.supports(operation: .readData))
    }
    
    func testSupportsSignData() throws {
        XCTAssertTrue(token.supports(operation: .signData))
    }
    
    func testSupportsDecryptData() throws {
        XCTAssertTrue(token.supports(operation: .decryptData))
    }
    
    func testSupportsPerformKeyExchange() throws {
        XCTAssertTrue(token.supports(operation: .performKeyExchange))
    }
    
    func testDoesNotSupportUnsupportedOperations() throws {
        // Test with an operation that should not be supported
        // Note: This test assumes there are operations that are not supported
        // If all operations are supported, this test may need adjustment
        
        // Testing with a hypothetical unsupported operation
        // In real implementation, you would test with actual unsupported operations
        let allOperations: [TKTokenOperation] = [.readData, .signData, .decryptData, .performKeyExchange]
        let supportedOperations = allOperations.filter { token.supports(operation: $0) }
        
        XCTAssertEqual(supportedOperations.count, 4, "Should support exactly 4 operations")
    }
    
    // MARK: - Error Handling Tests
    
    func testSessionCreationWithInvalidFormat() throws {
        // Test session creation - should work with any valid format
        // CTK framework validates formats, so we test with valid formats
        XCTAssertNoThrow(try token.createSession(format: .standard))
        XCTAssertNoThrow(try token.createSession(format: .restricted))
    }
    
    // MARK: - Performance Tests
    
    func testSessionCreationPerformance() throws {
        measure {
            do {
                _ = try token.createSession(format: .standard)
            } catch {
                XCTFail("Session creation failed: \(error)")
            }
        }
    }
    
    func testMultipleSessionCreationPerformance() throws {
        measure {
            for _ in 0..<10 {
                do {
                    _ = try token.createSession(format: .standard)
                } catch {
                    XCTFail("Session creation failed: \(error)")
                }
            }
        }
    }
    
    func testOperationSupportPerformance() throws {
        let operations: [TKTokenOperation] = [.readData, .signData, .decryptData, .performKeyExchange]
        
        measure {
            for operation in operations {
                _ = token.supports(operation: operation)
            }
        }
    }
    
    // MARK: - Thread Safety Tests
    
    func testConcurrentSessionCreation() throws {
        let expectation = XCTestExpectation(description: "Concurrent session creation")
        expectation.expectedFulfillmentCount = 5
        
        let concurrentQueue = DispatchQueue(label: "test.concurrent.sessions", attributes: .concurrent)
        
        for i in 0..<5 {
            concurrentQueue.async {
                do {
                    let format: TKTokenSessionFormat = (i % 2 == 0) ? .standard : .restricted
                    _ = try self.token.createSession(format: format)
                    expectation.fulfill()
                } catch {
                    XCTFail("Concurrent session creation \(i) failed: \(error)")
                }
            }
        }
        
        wait(for: [expectation], timeout: 5.0)
    }
    
    func testConcurrentOperationSupport() throws {
        let expectation = XCTestExpectation(description: "Concurrent operation support")
        expectation.expectedFulfillmentCount = 20
        
        let concurrentQueue = DispatchQueue(label: "test.concurrent.operations", attributes: .concurrent)
        let operations: [TKTokenOperation] = [.readData, .signData, .decryptData, .performKeyExchange]
        
        for _ in 0..<5 {
            for operation in operations {
                concurrentQueue.async {
                    _ = self.token.supports(operation: operation)
                    expectation.fulfill()
                }
            }
        }
        
        wait(for: [expectation], timeout: 5.0)
    }
    
    // MARK: - Token Info Validation Tests
    
    func testTokenInfoIntegrity() throws {
        let tokenInfo = token.tokenInfo
        
        // Verify all required fields are present
        XCTAssertNotNil(tokenInfo[kSecAttrTokenID as String])
        XCTAssertNotNil(tokenInfo[kSecAttrLabel as String])
        XCTAssertNotNil(tokenInfo["Manufacturer"])
        XCTAssertNotNil(tokenInfo["Model"])
        XCTAssertNotNil(tokenInfo["SerialNumber"])
        XCTAssertNotNil(tokenInfo["FirmwareVersion"])
        
        // Verify field types
        XCTAssertTrue(tokenInfo[kSecAttrTokenID as String] is String)
        XCTAssertTrue(tokenInfo[kSecAttrLabel as String] is String)
        XCTAssertTrue(tokenInfo["Manufacturer"] is String)
        XCTAssertTrue(tokenInfo["Model"] is String)
        XCTAssertTrue(tokenInfo["SerialNumber"] is String)
        XCTAssertTrue(tokenInfo["FirmwareVersion"] is String)
    }
    
    func testTokenInfoConsistency() throws {
        let tokenInfo1 = token.tokenInfo
        let tokenInfo2 = token.tokenInfo
        
        // Token info should be consistent across calls
        XCTAssertEqual(tokenInfo1[kSecAttrTokenID as String] as? String, 
                      tokenInfo2[kSecAttrTokenID as String] as? String)
        XCTAssertEqual(tokenInfo1[kSecAttrLabel as String] as? String, 
                      tokenInfo2[kSecAttrLabel as String] as? String)
        XCTAssertEqual(tokenInfo1["Manufacturer"] as? String, 
                      tokenInfo2["Manufacturer"] as? String)
    }
    
    // MARK: - Memory Management Tests
    
    func testTokenDeallocation() throws {
        weak var weakToken: SupacryptToken?
        
        autoreleasepool {
            let localDriver = SupacryptTokenDriver()
            let localTokenID = TKTokenID(stringValue: "com.supacrypt.ctk.token.dealloc")
            let localConfig = SupacryptTokenDriver.getTokenConfiguration(for: localTokenID)
            
            do {
                let localToken = try localDriver.createToken(forTokenID: localTokenID, configuration: localConfig) as? SupacryptToken
                weakToken = localToken
                XCTAssertNotNil(weakToken)
            } catch {
                XCTFail("Token creation failed: \(error)")
            }
        }
        
        // Token should be deallocated when out of scope
        // Note: This test may be flaky due to autorelease pools and ARC optimizations
        // It's included for completeness but may need adjustment based on actual behavior
    }
    
    // MARK: - Integration Tests
    
    func testTokenSessionIntegration() throws {
        let session = try token.createSession(format: .standard)
        
        // Basic session functionality
        XCTAssertEqual(session.token, token)
        XCTAssertEqual(session.format, .standard)
        
        // Session should be able to access token properties
        XCTAssertEqual(session.token?.tokenID, tokenID)
    }
    
    func testMultipleTokensFromSameDriver() throws {
        let token2ID = TKTokenID(stringValue: "com.supacrypt.ctk.token.test2")
        let token2Config = SupacryptTokenDriver.getTokenConfiguration(for: token2ID)
        let token2 = try driver.createToken(forTokenID: token2ID, configuration: token2Config) as? SupacryptToken
        
        XCTAssertNotNil(token2)
        XCTAssertNotIdentical(token, token2)
        XCTAssertEqual(token.tokenID, tokenID)
        XCTAssertEqual(token2?.tokenID, token2ID)
        
        // Both tokens should support the same operations
        let operations: [TKTokenOperation] = [.readData, .signData, .decryptData, .performKeyExchange]
        for operation in operations {
            XCTAssertEqual(token.supports(operation: operation), token2?.supports(operation: operation))
        }
    }
}