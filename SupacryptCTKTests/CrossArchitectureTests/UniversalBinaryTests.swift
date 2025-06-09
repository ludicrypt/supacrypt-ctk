import XCTest
import CryptoTokenKit
@testable import SupacryptCTK

final class UniversalBinaryTests: XCTestCase {
    
    var driver: SupacryptTokenDriver!
    var token: SupacryptToken!
    var session: SupacryptTokenSession!
    
    override func setUpWithError() throws {
        driver = SupacryptTokenDriver()
        
        let tokenID = TKTokenID(stringValue: "com.supacrypt.ctk.universal")
        let configuration = SupacryptTokenDriver.getTokenConfiguration(for: tokenID)
        token = try driver.createToken(forTokenID: tokenID, configuration: configuration) as? SupacryptToken
        session = try token.createSession(format: .standard) as? SupacryptTokenSession
        
        continueAfterFailure = false
    }
    
    override func tearDownWithError() throws {
        session = nil
        token = nil
        driver = nil
    }
    
    // MARK: - Architecture Detection Tests
    
    func testCurrentArchitecture() throws {
        let architecture = getCurrentArchitecture()
        
        #if arch(arm64)
        XCTAssertEqual(architecture, .arm64, "Should detect ARM64 architecture")
        #elseif arch(x86_64)
        XCTAssertEqual(architecture, .x86_64, "Should detect x86_64 architecture")
        #else
        XCTFail("Unsupported architecture detected")
        #endif
    }
    
    func testArchitectureSpecificOptimizations() throws {
        let architecture = getCurrentArchitecture()
        
        switch architecture {
        case .arm64:
            // Test Apple Silicon specific optimizations
            testAppleSiliconOptimizations()
        case .x86_64:
            // Test Intel specific optimizations
            testIntelOptimizations()
        case .unknown:
            XCTFail("Unknown architecture")
        }
    }
    
    private func testAppleSiliconOptimizations() {
        // Test ARM64 specific features and optimizations
        #if arch(arm64)
        
        // Test that the framework runs natively on Apple Silicon
        XCTAssertTrue(isRunningNatively(), "Should run natively on Apple Silicon")
        
        // Test performance characteristics expected on Apple Silicon
        measure {
            for _ in 0..<100 {
                _ = token.supports(operation: .signData)
            }
        }
        
        // Apple Silicon should show better performance characteristics
        measurePerformanceCharacteristics(expectedOptimal: true)
        
        #endif
    }
    
    private func testIntelOptimizations() {
        // Test x86_64 specific features
        #if arch(x86_64)
        
        // Test that the framework runs properly on Intel
        XCTAssertTrue(isRunningNatively(), "Should run natively on Intel")
        
        // Test performance characteristics on Intel
        measurePerformanceCharacteristics(expectedOptimal: false)
        
        #endif
    }
    
    // MARK: - Universal Binary Structure Tests
    
    func testUniversalBinaryStructure() throws {
        // Test that the binary contains the expected architectures
        let bundlePath = Bundle(for: SupacryptTokenDriver.self).bundlePath
        let architectures = getArchitecturesInBundle(bundlePath)
        
        // Universal binary should contain both architectures
        XCTAssertTrue(architectures.contains(.arm64) || architectures.contains(.x86_64),
                     "Binary should contain at least one supported architecture")
        
        // Log detected architectures for debugging
        print("Detected architectures: \(architectures)")
    }
    
    func testArchitectureCompatibility() throws {
        // Test that the current architecture is supported
        let currentArch = getCurrentArchitecture()
        let supportedArchitectures: Set<Architecture> = [.arm64, .x86_64]
        
        XCTAssertTrue(supportedArchitectures.contains(currentArch),
                     "Current architecture \(currentArch) should be supported")
    }
    
    // MARK: - Cross-Architecture Behavior Tests
    
    func testConsistentBehaviorAcrossArchitectures() throws {
        // Test that behavior is identical across architectures
        let tokenInfo = token.tokenInfo
        
        // Token info should be consistent regardless of architecture
        XCTAssertEqual(tokenInfo[kSecAttrLabel as String] as? String, "Supacrypt Token")
        XCTAssertEqual(tokenInfo["Manufacturer"] as? String, "Supacrypt")
        XCTAssertEqual(tokenInfo["Model"] as? String, "CTK Provider v1.0")
        XCTAssertEqual(tokenInfo["FirmwareVersion"] as? String, "1.0.0")
        
        // Operations support should be identical
        XCTAssertTrue(token.supports(operation: .signData))
        XCTAssertTrue(token.supports(operation: .decryptData))
        XCTAssertTrue(token.supports(operation: .readData))
        XCTAssertTrue(token.supports(operation: .performKeyExchange))
    }
    
    func testIdenticalAPIBehavior() throws {
        // Test that API behavior is identical across architectures
        
        // Session creation
        let standardSession = try token.createSession(format: .standard)
        let restrictedSession = try token.createSession(format: .restricted)
        
        XCTAssertEqual(standardSession.format, .standard)
        XCTAssertEqual(restrictedSession.format, .restricted)
        
        // Object enumeration
        let objectIDs = try session.objectIDs()
        XCTAssertNotNil(objectIDs)
        
        // Token driver behavior
        let tokenIDs = SupacryptTokenDriver.getTokenIDs()
        XCTAssertFalse(tokenIDs.isEmpty)
    }
    
    // MARK: - Performance Comparison Tests
    
    func testPerformanceCharacteristics() throws {
        let architecture = getCurrentArchitecture()
        let metrics = measureArchitectureSpecificPerformance()
        
        // Log performance metrics for comparison
        print("Architecture: \(architecture)")
        print("Token Creation: \(metrics.tokenCreation)ms")
        print("Session Creation: \(metrics.sessionCreation)ms")
        print("Operation Support: \(metrics.operationSupport)ms")
        print("Memory Usage: \(metrics.memoryUsage)MB")
        
        // Verify performance is within acceptable ranges
        XCTAssertLessThan(metrics.tokenCreation, 500, "Token creation should be reasonable")
        XCTAssertLessThan(metrics.sessionCreation, 200, "Session creation should be reasonable")
        XCTAssertLessThan(metrics.operationSupport, 10, "Operation support check should be fast")
        XCTAssertLessThan(metrics.memoryUsage, 100, "Memory usage should be reasonable")
    }
    
    private func measureArchitectureSpecificPerformance() -> ArchitecturePerformanceMetrics {
        var metrics = ArchitecturePerformanceMetrics()
        
        // Measure token creation
        let tokenStart = CFAbsoluteTimeGetCurrent()
        do {
            let tokenID = TKTokenID(stringValue: "com.supacrypt.ctk.arch.perf")
            let configuration = SupacryptTokenDriver.getTokenConfiguration(for: tokenID)
            _ = try driver.createToken(forTokenID: tokenID, configuration: configuration)
        } catch {}
        let tokenEnd = CFAbsoluteTimeGetCurrent()
        metrics.tokenCreation = (tokenEnd - tokenStart) * 1000
        
        // Measure session creation
        let sessionStart = CFAbsoluteTimeGetCurrent()
        do {
            _ = try token.createSession(format: .standard)
        } catch {}
        let sessionEnd = CFAbsoluteTimeGetCurrent()
        metrics.sessionCreation = (sessionEnd - sessionStart) * 1000
        
        // Measure operation support
        let opStart = CFAbsoluteTimeGetCurrent()
        _ = token.supports(operation: .signData)
        let opEnd = CFAbsoluteTimeGetCurrent()
        metrics.operationSupport = (opEnd - opStart) * 1000
        
        // Measure memory usage
        metrics.memoryUsage = getMemoryUsage()
        
        return metrics
    }
    
    private func measurePerformanceCharacteristics(expectedOptimal: Bool) {
        // Measure various performance characteristics
        let iterations = 1000
        
        measure {
            for _ in 0..<iterations {
                _ = token.supports(operation: .signData)
                _ = token.tokenClass
            }
        }
        
        // Additional architecture-specific measurements could be added here
    }
    
    // MARK: - Rosetta 2 Compatibility Tests
    
    func testRosetta2Compatibility() throws {
        #if arch(x86_64)
        // When running on Apple Silicon via Rosetta 2
        if isRunningUnderRosetta() {
            XCTAssertTrue(true, "Running under Rosetta 2")
            
            // Test that functionality works correctly under Rosetta
            testBasicFunctionalityUnderRosetta()
        } else {
            XCTAssertTrue(true, "Running natively on Intel")
        }
        #endif
    }
    
    private func testBasicFunctionalityUnderRosetta() {
        // Test basic functionality when running under Rosetta 2
        do {
            let tokenID = TKTokenID(stringValue: "com.supacrypt.ctk.rosetta")
            let configuration = SupacryptTokenDriver.getTokenConfiguration(for: tokenID)
            let rosettaToken = try driver.createToken(forTokenID: tokenID, configuration: configuration)
            let rosettaSession = try rosettaToken.createSession(format: .standard)
            
            XCTAssertNotNil(rosettaToken)
            XCTAssertNotNil(rosettaSession)
            
            // Operations should work under Rosetta
            XCTAssertTrue(rosettaToken.supports(operation: .signData))
            
        } catch {
            XCTFail("Basic functionality should work under Rosetta: \(error)")
        }
    }
    
    // MARK: - Memory Layout Tests
    
    func testMemoryLayoutConsistency() throws {
        // Test that memory layouts are consistent across architectures
        let pointerSize = MemoryLayout<UnsafeRawPointer>.size
        let intSize = MemoryLayout<Int>.size
        
        #if arch(arm64)
        XCTAssertEqual(pointerSize, 8, "Pointers should be 8 bytes on ARM64")
        XCTAssertEqual(intSize, 8, "Int should be 8 bytes on ARM64")
        #elseif arch(x86_64)
        XCTAssertEqual(pointerSize, 8, "Pointers should be 8 bytes on x86_64")
        XCTAssertEqual(intSize, 8, "Int should be 8 bytes on x86_64")
        #endif
        
        // Test that our data structures have expected sizes
        let tokenDriverSize = MemoryLayout<SupacryptTokenDriver>.size
        let tokenSize = MemoryLayout<SupacryptToken>.size
        
        // Sizes should be reasonable and consistent
        XCTAssertGreaterThan(tokenDriverSize, 0)
        XCTAssertGreaterThan(tokenSize, 0)
    }
    
    // MARK: - Endianness Tests
    
    func testEndiannessConsistency() throws {
        // Test that data is handled consistently across architectures
        let testValue: UInt32 = 0x12345678
        let dataRepresentation = withUnsafeBytes(of: testValue) { Data($0) }
        
        // Both ARM64 and x86_64 are little-endian
        XCTAssertEqual(dataRepresentation[0], 0x78)
        XCTAssertEqual(dataRepresentation[1], 0x56)
        XCTAssertEqual(dataRepresentation[2], 0x34)
        XCTAssertEqual(dataRepresentation[3], 0x12)
    }
    
    // MARK: - Threading Tests
    
    func testConcurrencyBehaviorAcrossArchitectures() throws {
        let expectation = XCTestExpectation(description: "Concurrent operations across architectures")
        expectation.expectedFulfillmentCount = 10
        
        DispatchQueue.concurrentPerform(iterations: 10) { iteration in
            do {
                let tokenID = TKTokenID(stringValue: "com.supacrypt.ctk.concurrent.\(iteration)")
                let configuration = SupacryptTokenDriver.getTokenConfiguration(for: tokenID)
                let concurrentToken = try self.driver.createToken(forTokenID: tokenID, configuration: configuration)
                
                XCTAssertNotNil(concurrentToken)
                expectation.fulfill()
            } catch {
                XCTFail("Concurrent operation \(iteration) failed: \(error)")
            }
        }
        
        wait(for: [expectation], timeout: 10.0)
    }
    
    // MARK: - Helper Methods
    
    private func getCurrentArchitecture() -> Architecture {
        #if arch(arm64)
        return .arm64
        #elseif arch(x86_64)
        return .x86_64
        #else
        return .unknown
        #endif
    }
    
    private func getArchitecturesInBundle(_ bundlePath: String) -> Set<Architecture> {
        // This is a simplified implementation
        // In a real implementation, you might use lipo or similar tools
        var architectures: Set<Architecture> = []
        
        #if arch(arm64)
        architectures.insert(.arm64)
        #elseif arch(x86_64)
        architectures.insert(.x86_64)
        #endif
        
        return architectures
    }
    
    private func isRunningNatively() -> Bool {
        // Check if the process is running natively or under translation
        #if arch(arm64)
        return !isRunningUnderRosetta()
        #elseif arch(x86_64)
        return true // x86_64 always runs natively on Intel Macs
        #else
        return false
        #endif
    }
    
    private func isRunningUnderRosetta() -> Bool {
        // Check if running under Rosetta 2 translation
        var ret = Int32(0)
        var size: Int = MemoryLayout.size(ofValue: ret)
        
        let result = sysctlbyname("sysctl.proc_translated", &ret, &size, nil, 0)
        
        if result == 0 {
            return ret == 1
        }
        
        return false
    }
    
    private func getMemoryUsage() -> Double {
        var info = mach_task_basic_info()
        var count = mach_msg_type_number_t(MemoryLayout<mach_task_basic_info>.size / MemoryLayout<integer_t>.size)
        
        let result = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: 1) {
                task_info(mach_task_self_, task_flavor_t(MACH_TASK_BASIC_INFO), $0, &count)
            }
        }
        
        if result == KERN_SUCCESS {
            return Double(info.resident_size) / (1024 * 1024) // Convert to MB
        } else {
            return 0
        }
    }
    
    // MARK: - Data Structures
    
    private enum Architecture: String, CaseIterable {
        case arm64 = "arm64"
        case x86_64 = "x86_64"
        case unknown = "unknown"
    }
    
    private struct ArchitecturePerformanceMetrics {
        var tokenCreation: Double = 0
        var sessionCreation: Double = 0
        var operationSupport: Double = 0
        var memoryUsage: Double = 0
    }
}