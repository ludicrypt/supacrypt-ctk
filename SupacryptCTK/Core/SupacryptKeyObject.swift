import Foundation
import CryptoTokenKit
import Security

public class SupacryptKeyObject: TKTokenObject {
    private let metadata: SupacryptKeyMetadata
    
    init(objectID: TKTokenObjectID, metadata: SupacryptKeyMetadata) {
        self.metadata = metadata
        super.init()
        self.objectID = objectID
    }
    
    public override var objectClass: TKTokenObjectClass {
        switch metadata.keyClass {
        case .publicKey:
            return .publicKey
        case .privateKey:
            return .privateKey
        }
    }
    
    public override var attributes: [String: Any] {
        var attrs: [String: Any] = [
            kSecAttrKeyType as String: metadata.keyType,
            kSecAttrKeySizeInBits as String: metadata.keySizeInBits,
            kSecAttrLabel as String: metadata.label,
            kSecAttrKeyClass as String: metadata.keyClass.rawValue,
            kSecAttrApplicationTag as String: metadata.applicationTag,
            kSecAttrTokenID as String: objectID.stringValue
        ]
        
        if let publicKeyData = metadata.publicKeyData {
            attrs[kSecValueData as String] = publicKeyData
        }
        
        attrs[kSecAttrCanSign as String] = metadata.canSign
        attrs[kSecAttrCanDecrypt as String] = metadata.canDecrypt
        attrs[kSecAttrCanDerive as String] = metadata.canDerive
        attrs[kSecAttrCanVerify as String] = metadata.canVerify
        attrs[kSecAttrCanEncrypt as String] = metadata.canEncrypt
        attrs[kSecAttrCanWrap as String] = metadata.canWrap
        attrs[kSecAttrCanUnwrap as String] = metadata.canUnwrap
        
        return attrs
    }
    
    public override var operations: [TKTokenOperation] {
        var ops: [TKTokenOperation] = []
        
        if metadata.canSign {
            ops.append(.signData)
        }
        
        if metadata.canDecrypt {
            ops.append(.decryptData)
        }
        
        if metadata.canDerive {
            ops.append(.performKeyExchange)
        }
        
        return ops
    }
}

public struct SupacryptKeyMetadata {
    let keyType: CFString
    let keySizeInBits: Int
    let label: String
    let keyClass: KeyClass
    let applicationTag: Data
    let publicKeyData: Data?
    let canSign: Bool
    let canDecrypt: Bool
    let canDerive: Bool
    let canVerify: Bool
    let canEncrypt: Bool
    let canWrap: Bool
    let canUnwrap: Bool
    
    public enum KeyClass: String {
        case publicKey = "public"
        case privateKey = "private"
        
        var secAttrValue: CFString {
            switch self {
            case .publicKey:
                return kSecAttrKeyClassPublic
            case .privateKey:
                return kSecAttrKeyClassPrivate
            }
        }
    }
    
    init(keyType: CFString,
         keySizeInBits: Int,
         label: String,
         keyClass: KeyClass,
         applicationTag: Data,
         publicKeyData: Data? = nil,
         canSign: Bool = false,
         canDecrypt: Bool = false,
         canDerive: Bool = false,
         canVerify: Bool = false,
         canEncrypt: Bool = false,
         canWrap: Bool = false,
         canUnwrap: Bool = false) {
        self.keyType = keyType
        self.keySizeInBits = keySizeInBits
        self.label = label
        self.keyClass = keyClass
        self.applicationTag = applicationTag
        self.publicKeyData = publicKeyData
        self.canSign = canSign
        self.canDecrypt = canDecrypt
        self.canDerive = canDerive
        self.canVerify = canVerify
        self.canEncrypt = canEncrypt
        self.canWrap = canWrap
        self.canUnwrap = canUnwrap
    }
}