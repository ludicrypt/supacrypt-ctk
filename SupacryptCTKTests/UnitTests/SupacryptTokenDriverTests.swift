import XCTest
import CryptoTokenKit
@testable import SupacryptCTK

final class SupacryptTokenDriverTests: XCTestCase {
    
    var driver: SupacryptTokenDriver!
    
    override func setUpWithError() throws {
        driver = SupacryptTokenDriver()
        continueAfterFailure = false
    }
    
    override func tearDownWithError() throws {
        driver = nil
    }
    
    // MARK: - Initialization Tests
    
    func testDriverInitialization() throws {
        XCTAssertNotNil(driver)
    }
    
    func testSharedInstanceSingleton() throws {
        let shared1 = SupacryptTokenDriver.shared
        let shared2 = SupacryptTokenDriver.shared
        
        XCTAssertIdentical(shared1, shared2, "Shared instance should be singleton")
    }
    
    // MARK: - Token Creation Tests
    
    func testCreateTokenSuccess() throws {
        let tokenID = TKTokenID(stringValue: "com.supacrypt.ctk.token.test")
        let configuration = TKTokenConfiguration()
        configuration.instanceID = tokenID.stringValue
        
        let token = try driver.createToken(forTokenID: tokenID, configuration: configuration)
        
        XCTAssertNotNil(token)
        XCTAssertEqual(token.tokenID, tokenID)
        XCTAssertTrue(token is SupacryptToken)
    }
    
    func testCreateTokenWithValidConfiguration() throws {
        let tokenID = TKTokenID(stringValue: "com.supacrypt.ctk.token.valid")
        let configuration = SupacryptTokenDriver.getTokenConfiguration(for: tokenID)
        
        let token = try driver.createToken(forTokenID: tokenID, configuration: configuration)
        
        XCTAssertNotNil(token)
        XCTAssertEqual(token.tokenID, tokenID)
        XCTAssertEqual(configuration.instanceID, tokenID.stringValue)
        XCTAssertEqual(configuration.keychainAccessGroup, "com.supacrypt.ctk")
    }
    
    func testCreateMultipleTokens() throws {
        let tokenID1 = TKTokenID(stringValue: "com.supacrypt.ctk.token.1")
        let tokenID2 = TKTokenID(stringValue: "com.supacrypt.ctk.token.2")
        
        let config1 = SupacryptTokenDriver.getTokenConfiguration(for: tokenID1)
        let config2 = SupacryptTokenDriver.getTokenConfiguration(for: tokenID2)
        
        let token1 = try driver.createToken(forTokenID: tokenID1, configuration: config1)
        let token2 = try driver.createToken(forTokenID: tokenID2, configuration: config2)
        
        XCTAssertNotNil(token1)
        XCTAssertNotNil(token2)
        XCTAssertNotIdentical(token1, token2)
        XCTAssertEqual(token1.tokenID, tokenID1)
        XCTAssertEqual(token2.tokenID, tokenID2)
    }
    
    // MARK: - Token Configuration Tests
    
    func testGetTokenIDs() throws {
        let tokenIDs = SupacryptTokenDriver.getTokenIDs()
        
        XCTAssertFalse(tokenIDs.isEmpty)
        XCTAssertTrue(tokenIDs.contains(TKTokenID(stringValue: "com.supacrypt.ctk.token")))
    }
    
    func testGetTokenConfiguration() throws {
        let tokenID = TKTokenID(stringValue: "com.supacrypt.ctk.token.config.test")
        let configuration = SupacryptTokenDriver.getTokenConfiguration(for: tokenID)
        
        XCTAssertNotNil(configuration)
        XCTAssertEqual(configuration.instanceID, tokenID.stringValue)
        XCTAssertEqual(configuration.keychainAccessGroup, "com.supacrypt.ctk")
    }
    
    func testConfigurationConsistency() throws {
        let tokenID = TKTokenID(stringValue: "com.supacrypt.ctk.token.consistency")
        
        let config1 = SupacryptTokenDriver.getTokenConfiguration(for: tokenID)
        let config2 = SupacryptTokenDriver.getTokenConfiguration(for: tokenID)
        
        XCTAssertEqual(config1.instanceID, config2.instanceID)
        XCTAssertEqual(config1.keychainAccessGroup, config2.keychainAccessGroup)
    }
    
    // MARK: - Lifecycle Tests
    
    func testDriverTermination() throws {
        // Test that termination doesn't throw
        XCTAssertNoThrow(driver.terminate())
    }
    
    func testDriverTerminationAfterTokenCreation() throws {
        let tokenID = TKTokenID(stringValue: "com.supacrypt.ctk.token.terminate")
        let configuration = SupacryptTokenDriver.getTokenConfiguration(for: tokenID)
        
        _ = try driver.createToken(forTokenID: tokenID, configuration: configuration)
        
        XCTAssertNoThrow(driver.terminate())
    }
    
    // MARK: - Error Handling Tests
    
    func testCreateTokenWithInvalidConfiguration() throws {
        let tokenID = TKTokenID(stringValue: "com.supacrypt.ctk.token.invalid")
        let configuration = TKTokenConfiguration()
        // Intentionally leave instanceID nil
        
        // Should still work as SupacryptToken handles missing instanceID
        XCTAssertNoThrow(try driver.createToken(forTokenID: tokenID, configuration: configuration))
    }
    
    // MARK: - Performance Tests
    
    func testTokenCreationPerformance() throws {
        let tokenID = TKTokenID(stringValue: "com.supacrypt.ctk.token.performance")
        let configuration = SupacryptTokenDriver.getTokenConfiguration(for: tokenID)
        
        measure {
            do {
                _ = try driver.createToken(forTokenID: tokenID, configuration: configuration)
            } catch {
                XCTFail("Token creation failed: \(error)")
            }
        }
    }
    
    func testMultipleTokenCreationPerformance() throws {
        measure {
            for i in 0..<10 {
                let tokenID = TKTokenID(stringValue: "com.supacrypt.ctk.token.perf.\(i)")
                let configuration = SupacryptTokenDriver.getTokenConfiguration(for: tokenID)
                
                do {
                    _ = try driver.createToken(forTokenID: tokenID, configuration: configuration)
                } catch {
                    XCTFail("Token creation \(i) failed: \(error)")
                }
            }
        }
    }
    
    // MARK: - Thread Safety Tests
    
    func testConcurrentTokenCreation() throws {
        let expectation = XCTestExpectation(description: "Concurrent token creation")
        expectation.expectedFulfillmentCount = 5
        
        let concurrentQueue = DispatchQueue(label: "test.concurrent", attributes: .concurrent)
        
        for i in 0..<5 {
            concurrentQueue.async {
                do {
                    let tokenID = TKTokenID(stringValue: "com.supacrypt.ctk.token.concurrent.\(i)")
                    let configuration = SupacryptTokenDriver.getTokenConfiguration(for: tokenID)
                    
                    _ = try self.driver.createToken(forTokenID: tokenID, configuration: configuration)
                    expectation.fulfill()
                } catch {
                    XCTFail("Concurrent token creation \(i) failed: \(error)")
                }
            }
        }
        
        wait(for: [expectation], timeout: 5.0)
    }
    
    func testSharedInstanceThreadSafety() throws {
        let expectation = XCTestExpectation(description: "Shared instance thread safety")
        expectation.expectedFulfillmentCount = 10
        
        let concurrentQueue = DispatchQueue(label: "test.shared", attributes: .concurrent)
        var instances: [SupacryptTokenDriver] = []
        let lock = NSLock()
        
        for _ in 0..<10 {
            concurrentQueue.async {
                let instance = SupacryptTokenDriver.shared
                
                lock.lock()
                instances.append(instance)
                lock.unlock()
                
                expectation.fulfill()
            }
        }
        
        wait(for: [expectation], timeout: 5.0)
        
        // All instances should be identical
        let firstInstance = instances.first!
        for instance in instances {
            XCTAssertIdentical(instance, firstInstance)
        }
    }
}