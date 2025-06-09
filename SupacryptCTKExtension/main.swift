import Foundation
import CryptoTokenKit
import OSLog

class SupacryptExtension: NSObject, TKTokenDriverDelegate {
    private let logger = OSLog(subsystem: "com.supacrypt.ctk.extension", category: "main")
    
    override init() {
        super.init()
        os_log("SupacryptExtension initialized", log: logger, type: .info)
    }
    
    func tokenDriver(_ driver: TKTokenDriver, 
                    createTokenForInstanceID instanceID: String, 
                    configuration: TKTokenConfiguration) throws -> TKToken {
        os_log("Creating token for instance ID: %{public}@", log: logger, type: .info, instanceID)
        
        let tokenID = TKTokenID(stringValue: instanceID)
        let token = try SupacryptToken(
            tokenID: tokenID,
            configuration: configuration,
            driver: driver as! SupacryptTokenDriver
        )
        
        os_log("Token created successfully for instance ID: %{public}@", log: logger, type: .info, instanceID)
        return token
    }
}

@main
struct SupacryptCTKExtensionMain {
    static func main() {
        let logger = OSLog(subsystem: "com.supacrypt.ctk.extension", category: "main")
        os_log("SupacryptCTK Extension starting", log: logger, type: .info)
        
        let extension = SupacryptExtension()
        let driver = SupacryptTokenDriver.shared
        driver.delegate = extension
        
        os_log("Token driver configured with delegate", log: logger, type: .info)
        
        // Configure token driver with supported token IDs
        let tokenIDs = SupacryptTokenDriver.getTokenIDs()
        os_log("Registering %{public}d token IDs", log: logger, type: .info, tokenIDs.count)
        
        for tokenID in tokenIDs {
            let config = SupacryptTokenDriver.getTokenConfiguration(for: tokenID)
            os_log("Configured token ID: %{public}@", log: logger, type: .debug, tokenID.stringValue)
        }
        
        // Start the extension's run loop
        os_log("Starting extension run loop", log: logger, type: .info)
        RunLoop.main.run()
    }
}