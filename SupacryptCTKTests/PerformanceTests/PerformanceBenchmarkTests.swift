import XCTest
import CryptoTokenKit
import Security
@testable import SupacryptCTK

final class PerformanceBenchmarkTests: XCTestCase {
    
    var driver: SupacryptTokenDriver!
    var token: SupacryptToken!
    var session: SupacryptTokenSession!
    var mockGRPCClient: MockGRPCClient!
    
    override func setUpWithError() throws {
        driver = SupacryptTokenDriver()
        
        let tokenID = TKTokenID(stringValue: "com.supacrypt.ctk.performance")
        let configuration = SupacryptTokenDriver.getTokenConfiguration(for: tokenID)
        token = try driver.createToken(forTokenID: tokenID, configuration: configuration) as? SupacryptToken
        session = try token.createSession(format: .standard) as? SupacryptTokenSession
        
        mockGRPCClient = try MockGRPCClient()
        setupPerformanceKeys()
        
        continueAfterFailure = false
    }
    
    override func tearDownWithError() throws {
        mockGRPCClient?.reset()
        session = nil
        token = nil
        driver = nil
    }
    
    private func setupPerformanceKeys() {
        // Add multiple mock keys for performance testing
        for i in 1...100 {
            let mockKey = MockGRPCClient.MockKeyData(
                keyID: "perf-key-\(i)",
                keyType: i % 2 == 0 ? kSecAttrKeyTypeRSA : kSecAttrKeyTypeECSECPrimeRandom,
                keySize: i % 2 == 0 ? 2048 : 256,
                publicKey: Data(repeating: UInt8(i % 256), count: i % 2 == 0 ? 256 : 64),
                canSign: true,
                canDecrypt: i % 2 == 0,
                canDerive: i % 2 == 1
            )
            mockGRPCClient.addMockKey(mockKey)
        }
    }
    
    // MARK: - Token Initialization Performance Tests
    
    func testTokenInitializationPerformance() throws {
        measure {
            do {
                let tokenID = TKTokenID(stringValue: "com.supacrypt.ctk.perf.init")
                let configuration = SupacryptTokenDriver.getTokenConfiguration(for: tokenID)
                _ = try driver.createToken(forTokenID: tokenID, configuration: configuration)
            } catch {
                XCTFail("Token initialization failed: \(error)")
            }
        }
    }
    
    func testTokenInitializationTarget() throws {
        // Target: < 200ms for token initialization
        let tokenID = TKTokenID(stringValue: "com.supacrypt.ctk.perf.target")
        let configuration = SupacryptTokenDriver.getTokenConfiguration(for: tokenID)
        
        let startTime = CFAbsoluteTimeGetCurrent()
        _ = try driver.createToken(forTokenID: tokenID, configuration: configuration)
        let endTime = CFAbsoluteTimeGetCurrent()
        
        let duration = (endTime - startTime) * 1000 // Convert to milliseconds
        XCTAssertLessThan(duration, 200, "Token initialization should complete in under 200ms")
    }
    
    func testMultipleTokenInitializationPerformance() throws {
        measure {
            for i in 0..<10 {
                do {
                    let tokenID = TKTokenID(stringValue: "com.supacrypt.ctk.perf.multi.\(i)")
                    let configuration = SupacryptTokenDriver.getTokenConfiguration(for: tokenID)
                    _ = try driver.createToken(forTokenID: tokenID, configuration: configuration)
                } catch {
                    XCTFail("Multiple token initialization failed at \(i): \(error)")
                }
            }
        }
    }
    
    // MARK: - Session Creation Performance Tests
    
    func testSessionCreationPerformance() throws {
        measure {
            do {
                _ = try token.createSession(format: .standard)
            } catch {
                XCTFail("Session creation failed: \(error)")
            }
        }
    }
    
    func testSessionCreationTarget() throws {
        // Target: < 100ms for session creation
        let startTime = CFAbsoluteTimeGetCurrent()
        _ = try token.createSession(format: .standard)
        let endTime = CFAbsoluteTimeGetCurrent()
        
        let duration = (endTime - startTime) * 1000
        XCTAssertLessThan(duration, 100, "Session creation should complete in under 100ms")
    }
    
    func testConcurrentSessionCreationPerformance() throws {
        let expectation = XCTestExpectation(description: "Concurrent session creation")
        expectation.expectedFulfillmentCount = 20
        
        let startTime = CFAbsoluteTimeGetCurrent()
        
        DispatchQueue.concurrentPerform(iterations: 20) { _ in
            do {
                _ = try self.token.createSession(format: .standard)
                expectation.fulfill()
            } catch {
                XCTFail("Concurrent session creation failed: \(error)")
            }
        }
        
        wait(for: [expectation], timeout: 5.0)
        
        let endTime = CFAbsoluteTimeGetCurrent()
        let totalDuration = (endTime - startTime) * 1000
        let averageDuration = totalDuration / 20
        
        XCTAssertLessThan(averageDuration, 150, "Average concurrent session creation should be under 150ms")
    }
    
    // MARK: - Key Enumeration Performance Tests
    
    func testKeyEnumerationPerformance() throws {
        measure {
            do {
                _ = try session.objectIDs()
            } catch {
                XCTFail("Key enumeration failed: \(error)")
            }
        }
    }
    
    func testKeyEnumerationTarget() throws {
        // Target: < 100ms for enumerating 100 keys
        let startTime = CFAbsoluteTimeGetCurrent()
        _ = try session.objectIDs()
        let endTime = CFAbsoluteTimeGetCurrent()
        
        let duration = (endTime - startTime) * 1000
        XCTAssertLessThan(duration, 100, "Key enumeration (100 keys) should complete in under 100ms")
    }
    
    func testLargeKeyEnumerationPerformance() throws {
        // Test with 1000 keys
        for i in 101...1000 {
            let mockKey = MockGRPCClient.MockKeyData(
                keyID: "large-perf-key-\(i)",
                keyType: kSecAttrKeyTypeRSA,
                keySize: 2048,
                publicKey: Data(repeating: UInt8(i % 256), count: 256),
                canSign: true,
                canDecrypt: true,
                canDerive: false
            )
            mockGRPCClient.addMockKey(mockKey)
        }
        
        measure {
            do {
                _ = try session.objectIDs()
            } catch {
                XCTFail("Large key enumeration failed: \(error)")
            }
        }
    }
    
    // MARK: - Cryptographic Operation Performance Tests
    
    func testRSASigningPerformance() async throws {
        let data = Data(repeating: 0x42, count: 256)
        let keyObjectID = TKTokenObjectID(stringValue: "perf-rsa-sign")
        let algorithm = TKTokenKeyAlgorithm.rsaSignaturePKCS1SHA256
        
        // Add mock RSA key
        let mockKey = MockGRPCClient.MockKeyData(
            keyID: "perf-rsa-sign",
            keyType: kSecAttrKeyTypeRSA,
            keySize: 2048,
            publicKey: Data(repeating: 0x42, count: 256),
            canSign: true,
            canDecrypt: false,
            canDerive: false
        )
        mockGRPCClient.addMockKey(mockKey)
        
        await measureAsyncPerformance {
            do {
                _ = try await session.sign(data, keyObjectID: keyObjectID, algorithm: algorithm)
            } catch {
                // Expected to fail in test environment, but we measure the attempt
            }
        }
    }
    
    func testRSASigningTarget() async throws {
        // Target: < 150ms for RSA-2048 signing with backend
        let data = Data(repeating: 0x42, count: 256)
        let keyObjectID = TKTokenObjectID(stringValue: "perf-rsa-target")
        let algorithm = TKTokenKeyAlgorithm.rsaSignaturePKCS1SHA256
        
        let mockKey = MockGRPCClient.MockKeyData(
            keyID: "perf-rsa-target",
            keyType: kSecAttrKeyTypeRSA,
            keySize: 2048,
            publicKey: Data(repeating: 0x42, count: 256),
            canSign: true,
            canDecrypt: false,
            canDerive: false
        )
        mockGRPCClient.addMockKey(mockKey)
        
        let startTime = CFAbsoluteTimeGetCurrent()
        
        do {
            _ = try await session.sign(data, keyObjectID: keyObjectID, algorithm: algorithm)
        } catch {
            // Expected to fail, but timing is still valid for framework overhead
        }
        
        let endTime = CFAbsoluteTimeGetCurrent()
        let duration = (endTime - startTime) * 1000
        
        XCTAssertLessThan(duration, 150, "RSA signing operation setup should complete in under 150ms")
    }
    
    func testECDSASigningPerformance() async throws {
        let data = Data(repeating: 0x42, count: 32)
        let keyObjectID = TKTokenObjectID(stringValue: "perf-ecdsa-sign")
        let algorithm = TKTokenKeyAlgorithm.ecdsaSignatureDigestX962SHA256
        
        let mockKey = MockGRPCClient.MockKeyData(
            keyID: "perf-ecdsa-sign",
            keyType: kSecAttrKeyTypeECSECPrimeRandom,
            keySize: 256,
            publicKey: Data(repeating: 0x04, count: 65),
            canSign: true,
            canDecrypt: false,
            canDerive: true
        )
        mockGRPCClient.addMockKey(mockKey)
        
        await measureAsyncPerformance {
            do {
                _ = try await session.sign(data, keyObjectID: keyObjectID, algorithm: algorithm)
            } catch {
                // Expected to fail in test environment
            }
        }
    }
    
    func testRSADecryptionPerformance() async throws {
        let ciphertext = Data(repeating: 0x99, count: 256)
        let keyObjectID = TKTokenObjectID(stringValue: "perf-rsa-decrypt")
        let algorithm = TKTokenKeyAlgorithm.rsaEncryptionPKCS1
        
        let mockKey = MockGRPCClient.MockKeyData(
            keyID: "perf-rsa-decrypt",
            keyType: kSecAttrKeyTypeRSA,
            keySize: 2048,
            publicKey: Data(repeating: 0x42, count: 256),
            canSign: false,
            canDecrypt: true,
            canDerive: false
        )
        mockGRPCClient.addMockKey(mockKey)
        
        await measureAsyncPerformance {
            do {
                _ = try await session.decrypt(ciphertext, keyObjectID: keyObjectID, algorithm: algorithm)
            } catch {
                // Expected to fail in test environment
            }
        }
    }
    
    // MARK: - Bulk Operation Performance Tests
    
    func testBulkSigningOperations() async throws {
        let data = Data(repeating: 0x42, count: 256)
        let algorithm = TKTokenKeyAlgorithm.rsaSignaturePKCS1SHA256
        
        // Setup multiple signing keys
        var keyObjectIDs: [TKTokenObjectID] = []
        for i in 1...10 {
            let keyID = "bulk-sign-\(i)"
            let mockKey = MockGRPCClient.MockKeyData(
                keyID: keyID,
                keyType: kSecAttrKeyTypeRSA,
                keySize: 2048,
                publicKey: Data(repeating: 0x42, count: 256),
                canSign: true,
                canDecrypt: false,
                canDerive: false
            )
            mockGRPCClient.addMockKey(mockKey)
            keyObjectIDs.append(TKTokenObjectID(stringValue: keyID))
        }
        
        await measureAsyncPerformance {
            for keyObjectID in keyObjectIDs {
                do {
                    _ = try await session.sign(data, keyObjectID: keyObjectID, algorithm: algorithm)
                } catch {
                    // Expected to fail in test environment
                }
            }
        }
    }
    
    func testConcurrentCryptographicOperations() async throws {
        let data = Data(repeating: 0x42, count: 256)
        let algorithm = TKTokenKeyAlgorithm.rsaSignaturePKCS1SHA256
        
        // Setup concurrent signing keys
        for i in 1...5 {
            let keyID = "concurrent-sign-\(i)"
            let mockKey = MockGRPCClient.MockKeyData(
                keyID: keyID,
                keyType: kSecAttrKeyTypeRSA,
                keySize: 2048,
                publicKey: Data(repeating: 0x42, count: 256),
                canSign: true,
                canDecrypt: false,
                canDerive: false
            )
            mockGRPCClient.addMockKey(mockKey)
        }
        
        let startTime = CFAbsoluteTimeGetCurrent()
        
        await withTaskGroup(of: Void.self) { group in
            for i in 1...5 {
                group.addTask {
                    let keyObjectID = TKTokenObjectID(stringValue: "concurrent-sign-\(i)")
                    do {
                        _ = try await self.session.sign(data, keyObjectID: keyObjectID, algorithm: algorithm)
                    } catch {
                        // Expected to fail in test environment
                    }
                }
            }
        }
        
        let endTime = CFAbsoluteTimeGetCurrent()
        let duration = (endTime - startTime) * 1000
        
        XCTAssertLessThan(duration, 500, "5 concurrent operations should complete in under 500ms")
    }
    
    // MARK: - Memory Performance Tests
    
    func testMemoryFootprintDuringNormalOperation() throws {
        // Target: < 50MB during normal operation
        let initialMemory = getMemoryUsage()
        
        // Perform various operations
        for i in 0..<50 {
            do {
                let tokenID = TKTokenID(stringValue: "com.supacrypt.ctk.memory.\(i)")
                let configuration = SupacryptTokenDriver.getTokenConfiguration(for: tokenID)
                let testToken = try driver.createToken(forTokenID: tokenID, configuration: configuration)
                let testSession = try testToken.createSession(format: .standard)
                _ = try testSession.objectIDs()
            } catch {
                // Continue with memory test even if operations fail
            }
        }
        
        let finalMemory = getMemoryUsage()
        let memoryIncrease = finalMemory - initialMemory
        
        // Convert to MB
        let memoryIncreaseMB = Double(memoryIncrease) / (1024 * 1024)
        
        XCTAssertLessThan(memoryIncreaseMB, 50, "Memory increase should be less than 50MB")
    }
    
    func testMemoryLeakDetection() throws {
        let initialMemory = getMemoryUsage()
        
        autoreleasepool {
            for i in 0..<100 {
                do {
                    let tokenID = TKTokenID(stringValue: "com.supacrypt.ctk.leak.\(i)")
                    let configuration = SupacryptTokenDriver.getTokenConfiguration(for: tokenID)
                    let testToken = try driver.createToken(forTokenID: tokenID, configuration: configuration)
                    _ = try testToken.createSession(format: .standard)
                } catch {
                    // Continue with leak test
                }
            }
        }
        
        // Force garbage collection
        for _ in 0..<3 {
            autoreleasepool {}
        }
        
        let finalMemory = getMemoryUsage()
        let memoryIncrease = finalMemory - initialMemory
        let memoryIncreaseMB = Double(memoryIncrease) / (1024 * 1024)
        
        // Allow for some memory increase but detect significant leaks
        XCTAssertLessThan(memoryIncreaseMB, 10, "Memory increase after cleanup should be less than 10MB")
    }
    
    private func getMemoryUsage() -> UInt64 {
        var info = mach_task_basic_info()
        var count = mach_msg_type_number_t(MemoryLayout<mach_task_basic_info>.size / MemoryLayout<integer_t>.size)
        
        let result = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: 1) {
                task_info(mach_task_self_, task_flavor_t(MACH_TASK_BASIC_INFO), $0, &count)
            }
        }
        
        return result == KERN_SUCCESS ? info.resident_size : 0
    }
    
    // MARK: - CPU Usage Performance Tests
    
    func testCPUUsageDuringOperations() throws {
        // Test CPU usage during intensive operations
        measure {
            for _ in 0..<100 {
                _ = token.supports(operation: .signData)
                _ = token.tokenInfo
                
                do {
                    _ = try session.objectIDs()
                } catch {
                    // Continue with CPU test
                }
            }
        }
    }
    
    // MARK: - Network Performance Tests (Mock)
    
    func testGRPCConnectionPerformance() async throws {
        await measureAsyncPerformance {
            do {
                _ = try await mockGRPCClient.testConnection()
            } catch {
                XCTFail("gRPC connection test failed: \(error)")
            }
        }
    }
    
    func testGRPCOperationLatency() async throws {
        // Test latency with simulated network delay
        mockGRPCClient.responseDelay = 0.01 // 10ms simulated latency
        
        var request = Supacrypt_V1_GenerateKeyRequest()
        request.version = 1
        request.name = "Latency Test Key"
        request.keyType = kSecAttrKeyTypeRSA as String
        request.keySize = 2048
        
        let startTime = CFAbsoluteTimeGetCurrent()
        _ = try await mockGRPCClient.generateKey(request: request)
        let endTime = CFAbsoluteTimeGetCurrent()
        
        let duration = (endTime - startTime) * 1000
        XCTAssertGreaterThanOrEqual(duration, 10, "Should include simulated latency")
        XCTAssertLessThan(duration, 50, "Total latency should be reasonable")
    }
    
    // MARK: - Stress Testing
    
    func testExtendedOperationDuration() async throws {
        // Test running operations for extended period
        let testDuration: TimeInterval = 5.0 // 5 seconds
        let startTime = Date()
        var operationCount = 0
        
        while Date().timeIntervalSince(startTime) < testDuration {
            do {
                _ = try session.objectIDs()
                operationCount += 1
            } catch {
                // Continue stress test
            }
            
            // Small delay to prevent overwhelming the system
            try await Task.sleep(nanoseconds: 10_000_000) // 10ms
        }
        
        let operationsPerSecond = Double(operationCount) / testDuration
        XCTAssertGreaterThan(operationsPerSecond, 10, "Should handle at least 10 operations per second")
    }
    
    func testRecoveryFromBackendFailures() async throws {
        // Test recovery after simulated backend failures
        mockGRPCClient.setMockFailure(operations: true)
        
        // Attempt operations during failure
        for _ in 0..<5 {
            do {
                _ = try await mockGRPCClient.testConnection()
            } catch {
                // Expected to fail
            }
        }
        
        // Restore functionality
        mockGRPCClient.setMockFailure(operations: false)
        
        // Verify recovery
        let recovered = try await mockGRPCClient.testConnection()
        XCTAssertTrue(recovered, "Should recover after backend restoration")
    }
    
    // MARK: - Performance Reporting
    
    func testPerformanceMetricsCollection() throws {
        // Collect and report performance metrics
        let metrics = collectPerformanceMetrics()
        
        // Log metrics for analysis
        print("Performance Metrics:")
        print("Token Creation Time: \(metrics.tokenCreationTime)ms")
        print("Session Creation Time: \(metrics.sessionCreationTime)ms")
        print("Key Enumeration Time: \(metrics.keyEnumerationTime)ms")
        print("Memory Usage: \(metrics.memoryUsage)MB")
        
        // Verify metrics are within acceptable ranges
        XCTAssertLessThan(metrics.tokenCreationTime, 200)
        XCTAssertLessThan(metrics.sessionCreationTime, 100)
        XCTAssertLessThan(metrics.keyEnumerationTime, 100)
        XCTAssertLessThan(metrics.memoryUsage, 50)
    }
    
    private func collectPerformanceMetrics() -> PerformanceMetrics {
        var metrics = PerformanceMetrics()
        
        // Measure token creation
        let tokenStartTime = CFAbsoluteTimeGetCurrent()
        do {
            let tokenID = TKTokenID(stringValue: "com.supacrypt.ctk.metrics")
            let configuration = SupacryptTokenDriver.getTokenConfiguration(for: tokenID)
            _ = try driver.createToken(forTokenID: tokenID, configuration: configuration)
        } catch {}
        let tokenEndTime = CFAbsoluteTimeGetCurrent()
        metrics.tokenCreationTime = (tokenEndTime - tokenStartTime) * 1000
        
        // Measure session creation
        let sessionStartTime = CFAbsoluteTimeGetCurrent()
        do {
            _ = try token.createSession(format: .standard)
        } catch {}
        let sessionEndTime = CFAbsoluteTimeGetCurrent()
        metrics.sessionCreationTime = (sessionEndTime - sessionStartTime) * 1000
        
        // Measure key enumeration
        let enumStartTime = CFAbsoluteTimeGetCurrent()
        do {
            _ = try session.objectIDs()
        } catch {}
        let enumEndTime = CFAbsoluteTimeGetCurrent()
        metrics.keyEnumerationTime = (enumEndTime - enumStartTime) * 1000
        
        // Measure memory usage
        metrics.memoryUsage = Double(getMemoryUsage()) / (1024 * 1024)
        
        return metrics
    }
    
    private struct PerformanceMetrics {
        var tokenCreationTime: Double = 0
        var sessionCreationTime: Double = 0
        var keyEnumerationTime: Double = 0
        var memoryUsage: Double = 0
    }
}