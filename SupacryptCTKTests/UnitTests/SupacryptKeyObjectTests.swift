import XCTest
import CryptoTokenKit
import Security
@testable import SupacryptCTK

final class SupacryptKeyObjectTests: XCTestCase {
    
    var rsaPrivateKeyObject: SupacryptKeyObject!
    var rsaPublicKeyObject: SupacryptKeyObject!
    var ecPrivateKeyObject: SupacryptKeyObject!
    var ecPublicKeyObject: SupacryptKeyObject!
    
    override func setUpWithError() throws {
        // Create RSA private key object
        let rsaPrivateMetadata = SupacryptKeyMetadata(
            keyType: kSecAttrKeyTypeRSA,
            keySizeInBits: 2048,
            label: "Test RSA Private Key",
            keyClass: .privateKey,
            applicationTag: "rsa-private-test".data(using: .utf8)!,
            publicKeyData: Data(repeating: 0x42, count: 256),
            canSign: true,
            canDecrypt: true,
            canDerive: false,
            canVerify: false,
            canEncrypt: false,
            canWrap: false,
            canUnwrap: false
        )
        
        rsaPrivateKeyObject = SupacryptKeyObject(
            objectID: TKTokenObjectID(stringValue: "rsa.private.test"),
            metadata: rsaPrivateMetadata
        )
        
        // Create RSA public key object
        let rsaPublicMetadata = SupacryptKeyMetadata(
            keyType: kSecAttrKeyTypeRSA,
            keySizeInBits: 2048,
            label: "Test RSA Public Key",
            keyClass: .publicKey,
            applicationTag: "rsa-public-test".data(using: .utf8)!,
            publicKeyData: Data(repeating: 0x42, count: 256),
            canSign: false,
            canDecrypt: false,
            canDerive: false,
            canVerify: true,
            canEncrypt: true,
            canWrap: true,
            canUnwrap: false
        )
        
        rsaPublicKeyObject = SupacryptKeyObject(
            objectID: TKTokenObjectID(stringValue: "rsa.public.test"),
            metadata: rsaPublicMetadata
        )
        
        // Create EC private key object
        let ecPrivateMetadata = SupacryptKeyMetadata(
            keyType: kSecAttrKeyTypeECSECPrimeRandom,
            keySizeInBits: 256,
            label: "Test EC Private Key",
            keyClass: .privateKey,
            applicationTag: "ec-private-test".data(using: .utf8)!,
            publicKeyData: Data(repeating: 0x04, count: 65), // Uncompressed EC public key
            canSign: true,
            canDecrypt: false,
            canDerive: true,
            canVerify: false,
            canEncrypt: false,
            canWrap: false,
            canUnwrap: false
        )
        
        ecPrivateKeyObject = SupacryptKeyObject(
            objectID: TKTokenObjectID(stringValue: "ec.private.test"),
            metadata: ecPrivateMetadata
        )
        
        // Create EC public key object
        let ecPublicMetadata = SupacryptKeyMetadata(
            keyType: kSecAttrKeyTypeECSECPrimeRandom,
            keySizeInBits: 256,
            label: "Test EC Public Key",
            keyClass: .publicKey,
            applicationTag: "ec-public-test".data(using: .utf8)!,
            publicKeyData: Data(repeating: 0x04, count: 65),
            canSign: false,
            canDecrypt: false,
            canDerive: false,
            canVerify: true,
            canEncrypt: false,
            canWrap: false,
            canUnwrap: false
        )
        
        ecPublicKeyObject = SupacryptKeyObject(
            objectID: TKTokenObjectID(stringValue: "ec.public.test"),
            metadata: ecPublicMetadata
        )
        
        continueAfterFailure = false
    }
    
    override func tearDownWithError() throws {
        rsaPrivateKeyObject = nil
        rsaPublicKeyObject = nil
        ecPrivateKeyObject = nil
        ecPublicKeyObject = nil
    }
    
    // MARK: - Initialization Tests
    
    func testRSAPrivateKeyInitialization() throws {
        XCTAssertNotNil(rsaPrivateKeyObject)
        XCTAssertEqual(rsaPrivateKeyObject.objectID.stringValue, "rsa.private.test")
        XCTAssertEqual(rsaPrivateKeyObject.objectClass, .privateKey)
    }
    
    func testRSAPublicKeyInitialization() throws {
        XCTAssertNotNil(rsaPublicKeyObject)
        XCTAssertEqual(rsaPublicKeyObject.objectID.stringValue, "rsa.public.test")
        XCTAssertEqual(rsaPublicKeyObject.objectClass, .publicKey)
    }
    
    func testECPrivateKeyInitialization() throws {
        XCTAssertNotNil(ecPrivateKeyObject)
        XCTAssertEqual(ecPrivateKeyObject.objectID.stringValue, "ec.private.test")
        XCTAssertEqual(ecPrivateKeyObject.objectClass, .privateKey)
    }
    
    func testECPublicKeyInitialization() throws {
        XCTAssertNotNil(ecPublicKeyObject)
        XCTAssertEqual(ecPublicKeyObject.objectID.stringValue, "ec.public.test")
        XCTAssertEqual(ecPublicKeyObject.objectClass, .publicKey)
    }
    
    // MARK: - Attributes Tests
    
    func testRSAPrivateKeyAttributes() throws {
        let attributes = rsaPrivateKeyObject.attributes
        
        XCTAssertEqual(attributes[kSecAttrKeyType as String] as? CFString, kSecAttrKeyTypeRSA)
        XCTAssertEqual(attributes[kSecAttrKeySizeInBits as String] as? Int, 2048)
        XCTAssertEqual(attributes[kSecAttrLabel as String] as? String, "Test RSA Private Key")
        XCTAssertEqual(attributes[kSecAttrKeyClass as String] as? CFString, kSecAttrKeyClassPrivate)
        XCTAssertEqual(attributes[kSecAttrApplicationTag as String] as? Data, "rsa-private-test".data(using: .utf8))
        XCTAssertEqual(attributes[kSecAttrTokenID as String] as? String, "rsa.private.test")
        
        // Capability attributes
        XCTAssertEqual(attributes[kSecAttrCanSign as String] as? Bool, true)
        XCTAssertEqual(attributes[kSecAttrCanDecrypt as String] as? Bool, true)
        XCTAssertEqual(attributes[kSecAttrCanDerive as String] as? Bool, false)
        XCTAssertEqual(attributes[kSecAttrCanVerify as String] as? Bool, false)
        XCTAssertEqual(attributes[kSecAttrCanEncrypt as String] as? Bool, false)
        XCTAssertEqual(attributes[kSecAttrCanWrap as String] as? Bool, false)
        XCTAssertEqual(attributes[kSecAttrCanUnwrap as String] as? Bool, false)
        
        // Public key data
        XCTAssertNotNil(attributes[kSecValueData as String] as? Data)
    }
    
    func testRSAPublicKeyAttributes() throws {
        let attributes = rsaPublicKeyObject.attributes
        
        XCTAssertEqual(attributes[kSecAttrKeyType as String] as? CFString, kSecAttrKeyTypeRSA)
        XCTAssertEqual(attributes[kSecAttrKeySizeInBits as String] as? Int, 2048)
        XCTAssertEqual(attributes[kSecAttrLabel as String] as? String, "Test RSA Public Key")
        XCTAssertEqual(attributes[kSecAttrKeyClass as String] as? CFString, kSecAttrKeyClassPublic)
        XCTAssertEqual(attributes[kSecAttrApplicationTag as String] as? Data, "rsa-public-test".data(using: .utf8))
        
        // Capability attributes
        XCTAssertEqual(attributes[kSecAttrCanSign as String] as? Bool, false)
        XCTAssertEqual(attributes[kSecAttrCanDecrypt as String] as? Bool, false)
        XCTAssertEqual(attributes[kSecAttrCanDerive as String] as? Bool, false)
        XCTAssertEqual(attributes[kSecAttrCanVerify as String] as? Bool, true)
        XCTAssertEqual(attributes[kSecAttrCanEncrypt as String] as? Bool, true)
        XCTAssertEqual(attributes[kSecAttrCanWrap as String] as? Bool, true)
        XCTAssertEqual(attributes[kSecAttrCanUnwrap as String] as? Bool, false)
    }
    
    func testECPrivateKeyAttributes() throws {
        let attributes = ecPrivateKeyObject.attributes
        
        XCTAssertEqual(attributes[kSecAttrKeyType as String] as? CFString, kSecAttrKeyTypeECSECPrimeRandom)
        XCTAssertEqual(attributes[kSecAttrKeySizeInBits as String] as? Int, 256)
        XCTAssertEqual(attributes[kSecAttrLabel as String] as? String, "Test EC Private Key")
        XCTAssertEqual(attributes[kSecAttrKeyClass as String] as? CFString, kSecAttrKeyClassPrivate)
        
        // EC-specific capabilities
        XCTAssertEqual(attributes[kSecAttrCanSign as String] as? Bool, true)
        XCTAssertEqual(attributes[kSecAttrCanDerive as String] as? Bool, true)
        XCTAssertEqual(attributes[kSecAttrCanDecrypt as String] as? Bool, false)
    }
    
    func testECPublicKeyAttributes() throws {
        let attributes = ecPublicKeyObject.attributes
        
        XCTAssertEqual(attributes[kSecAttrKeyType as String] as? CFString, kSecAttrKeyTypeECSECPrimeRandom)
        XCTAssertEqual(attributes[kSecAttrKeySizeInBits as String] as? Int, 256)
        XCTAssertEqual(attributes[kSecAttrKeyClass as String] as? CFString, kSecAttrKeyClassPublic)
        
        // EC public key capabilities
        XCTAssertEqual(attributes[kSecAttrCanVerify as String] as? Bool, true)
        XCTAssertEqual(attributes[kSecAttrCanSign as String] as? Bool, false)
        XCTAssertEqual(attributes[kSecAttrCanDerive as String] as? Bool, false)
    }
    
    // MARK: - Operations Tests
    
    func testRSAPrivateKeyOperations() throws {
        let operations = rsaPrivateKeyObject.operations
        
        XCTAssertTrue(operations.contains(.signData))
        XCTAssertTrue(operations.contains(.decryptData))
        XCTAssertFalse(operations.contains(.performKeyExchange))
    }
    
    func testRSAPublicKeyOperations() throws {
        let operations = rsaPublicKeyObject.operations
        
        XCTAssertFalse(operations.contains(.signData))
        XCTAssertFalse(operations.contains(.decryptData))
        XCTAssertFalse(operations.contains(.performKeyExchange))
    }
    
    func testECPrivateKeyOperations() throws {
        let operations = ecPrivateKeyObject.operations
        
        XCTAssertTrue(operations.contains(.signData))
        XCTAssertFalse(operations.contains(.decryptData))
        XCTAssertTrue(operations.contains(.performKeyExchange))
    }
    
    func testECPublicKeyOperations() throws {
        let operations = ecPublicKeyObject.operations
        
        XCTAssertFalse(operations.contains(.signData))
        XCTAssertFalse(operations.contains(.decryptData))
        XCTAssertFalse(operations.contains(.performKeyExchange))
    }
    
    // MARK: - Metadata Tests
    
    func testSupacryptKeyMetadataCreation() throws {
        let metadata = SupacryptKeyMetadata(
            keyType: kSecAttrKeyTypeRSA,
            keySizeInBits: 4096,
            label: "Test Custom Key",
            keyClass: .privateKey,
            applicationTag: "custom-tag".data(using: .utf8)!,
            publicKeyData: Data(repeating: 0xFF, count: 512),
            canSign: true,
            canDecrypt: true,
            canDerive: false,
            canVerify: false,
            canEncrypt: false,
            canWrap: true,
            canUnwrap: true
        )
        
        XCTAssertEqual(metadata.keyType, kSecAttrKeyTypeRSA)
        XCTAssertEqual(metadata.keySizeInBits, 4096)
        XCTAssertEqual(metadata.label, "Test Custom Key")
        XCTAssertEqual(metadata.keyClass, .privateKey)
        XCTAssertEqual(metadata.applicationTag, "custom-tag".data(using: .utf8)!)
        XCTAssertEqual(metadata.publicKeyData, Data(repeating: 0xFF, count: 512))
        XCTAssertTrue(metadata.canSign)
        XCTAssertTrue(metadata.canDecrypt)
        XCTAssertFalse(metadata.canDerive)
        XCTAssertFalse(metadata.canVerify)
        XCTAssertFalse(metadata.canEncrypt)
        XCTAssertTrue(metadata.canWrap)
        XCTAssertTrue(metadata.canUnwrap)
    }
    
    func testKeyClassEnum() throws {
        XCTAssertEqual(SupacryptKeyMetadata.KeyClass.privateKey.secAttrValue, kSecAttrKeyClassPrivate)
        XCTAssertEqual(SupacryptKeyMetadata.KeyClass.publicKey.secAttrValue, kSecAttrKeyClassPublic)
        
        XCTAssertEqual(SupacryptKeyMetadata.KeyClass.privateKey.rawValue, "private")
        XCTAssertEqual(SupacryptKeyMetadata.KeyClass.publicKey.rawValue, "public")
    }
    
    // MARK: - Edge Cases Tests
    
    func testKeyObjectWithMinimalMetadata() throws {
        let minimalMetadata = SupacryptKeyMetadata(
            keyType: kSecAttrKeyTypeRSA,
            keySizeInBits: 1024,
            label: "Minimal",
            keyClass: .privateKey,
            applicationTag: Data()
        )
        
        let keyObject = SupacryptKeyObject(
            objectID: TKTokenObjectID(stringValue: "minimal.test"),
            metadata: minimalMetadata
        )
        
        XCTAssertNotNil(keyObject)
        XCTAssertEqual(keyObject.objectClass, .privateKey)
        
        let attributes = keyObject.attributes
        XCTAssertEqual(attributes[kSecAttrKeySizeInBits as String] as? Int, 1024)
        XCTAssertEqual(attributes[kSecAttrLabel as String] as? String, "Minimal")
        
        // Should have no operations since all capabilities are false by default
        XCTAssertTrue(keyObject.operations.isEmpty)
    }
    
    func testKeyObjectWithoutPublicKeyData() throws {
        let metadataWithoutPublicKey = SupacryptKeyMetadata(
            keyType: kSecAttrKeyTypeRSA,
            keySizeInBits: 2048,
            label: "No Public Key Data",
            keyClass: .privateKey,
            applicationTag: "no-public-key".data(using: .utf8)!,
            publicKeyData: nil,
            canSign: true
        )
        
        let keyObject = SupacryptKeyObject(
            objectID: TKTokenObjectID(stringValue: "no.public.key"),
            metadata: metadataWithoutPublicKey
        )
        
        let attributes = keyObject.attributes
        XCTAssertNil(attributes[kSecValueData as String] as? Data)
        XCTAssertTrue(keyObject.operations.contains(.signData))
    }
    
    // MARK: - Performance Tests
    
    func testAttributesPerformance() throws {
        measure {
            _ = rsaPrivateKeyObject.attributes
        }
    }
    
    func testOperationsPerformance() throws {
        measure {
            _ = rsaPrivateKeyObject.operations
        }
    }
    
    func testKeyObjectCreationPerformance() throws {
        let metadata = SupacryptKeyMetadata(
            keyType: kSecAttrKeyTypeRSA,
            keySizeInBits: 2048,
            label: "Performance Test",
            keyClass: .privateKey,
            applicationTag: "perf-test".data(using: .utf8)!,
            canSign: true,
            canDecrypt: true
        )
        
        measure {
            _ = SupacryptKeyObject(
                objectID: TKTokenObjectID(stringValue: "perf.test"),
                metadata: metadata
            )
        }
    }
    
    // MARK: - Memory Tests
    
    func testKeyObjectMemoryFootprint() throws {
        var keyObjects: [SupacryptKeyObject] = []
        
        // Create multiple key objects to test memory usage
        for i in 0..<100 {
            let metadata = SupacryptKeyMetadata(
                keyType: kSecAttrKeyTypeRSA,
                keySizeInBits: 2048,
                label: "Memory Test \(i)",
                keyClass: .privateKey,
                applicationTag: "memory-test-\(i)".data(using: .utf8)!,
                publicKeyData: Data(repeating: UInt8(i % 256), count: 256),
                canSign: true
            )
            
            let keyObject = SupacryptKeyObject(
                objectID: TKTokenObjectID(stringValue: "memory.test.\(i)"),
                metadata: metadata
            )
            
            keyObjects.append(keyObject)
        }
        
        XCTAssertEqual(keyObjects.count, 100)
        
        // Test that all objects are properly initialized
        for (index, keyObject) in keyObjects.enumerated() {
            XCTAssertEqual(keyObject.objectID.stringValue, "memory.test.\(index)")
            XCTAssertEqual(keyObject.objectClass, .privateKey)
        }
    }
    
    // MARK: - Consistency Tests
    
    func testAttributesConsistency() throws {
        let attributes1 = rsaPrivateKeyObject.attributes
        let attributes2 = rsaPrivateKeyObject.attributes
        
        // Attributes should be consistent across multiple calls
        XCTAssertEqual(attributes1.count, attributes2.count)
        
        for (key, value1) in attributes1 {
            let value2 = attributes2[key]
            XCTAssertNotNil(value2, "Key \(key) missing in second call")
            
            // Compare values (handling different data types)
            if let data1 = value1 as? Data, let data2 = value2 as? Data {
                XCTAssertEqual(data1, data2)
            } else if let string1 = value1 as? String, let string2 = value2 as? String {
                XCTAssertEqual(string1, string2)
            } else if let int1 = value1 as? Int, let int2 = value2 as? Int {
                XCTAssertEqual(int1, int2)
            } else if let bool1 = value1 as? Bool, let bool2 = value2 as? Bool {
                XCTAssertEqual(bool1, bool2)
            }
        }
    }
    
    func testOperationsConsistency() throws {
        let operations1 = rsaPrivateKeyObject.operations
        let operations2 = rsaPrivateKeyObject.operations
        
        XCTAssertEqual(operations1.count, operations2.count)
        XCTAssertEqual(Set(operations1), Set(operations2))
    }
    
    // MARK: - Validation Tests
    
    func testKeyTypeValidation() throws {
        let supportedTypes: [CFString] = [
            kSecAttrKeyTypeRSA,
            kSecAttrKeyTypeECSECPrimeRandom
        ]
        
        for keyType in supportedTypes {
            let metadata = SupacryptKeyMetadata(
                keyType: keyType,
                keySizeInBits: 2048,
                label: "Type Test",
                keyClass: .privateKey,
                applicationTag: "type-test".data(using: .utf8)!
            )
            
            let keyObject = SupacryptKeyObject(
                objectID: TKTokenObjectID(stringValue: "type.test"),
                metadata: metadata
            )
            
            let attributes = keyObject.attributes
            XCTAssertEqual(attributes[kSecAttrKeyType as String] as? CFString, keyType)
        }
    }
    
    func testKeySizeValidation() throws {
        let validSizes = [1024, 2048, 3072, 4096, 256, 384, 521]
        
        for keySize in validSizes {
            let metadata = SupacryptKeyMetadata(
                keyType: kSecAttrKeyTypeRSA,
                keySizeInBits: keySize,
                label: "Size Test",
                keyClass: .privateKey,
                applicationTag: "size-test".data(using: .utf8)!
            )
            
            let keyObject = SupacryptKeyObject(
                objectID: TKTokenObjectID(stringValue: "size.test"),
                metadata: metadata
            )
            
            let attributes = keyObject.attributes
            XCTAssertEqual(attributes[kSecAttrKeySizeInBits as String] as? Int, keySize)
        }
    }
}