import NIO
import NIOSSH
import Crypto

/// Represents an authentication method.
public final class SSHAuthenticationMethod: NIOSSHClientUserAuthenticationDelegate {
    private enum Implementation {
        case custom(NIOSSHClientUserAuthenticationDelegate)
        case user(String, offer: NIOSSHUserAuthenticationOffer.Offer)
    }
    
    private let allImplementations: [Implementation]
    private var implementations: [Implementation]
    
    internal init(
        username: String,
        offer: NIOSSHUserAuthenticationOffer.Offer
    ) {
        self.allImplementations = [.user(username, offer: offer)]
        self.implementations = allImplementations
    }
    
    internal init(
        custom: NIOSSHClientUserAuthenticationDelegate
    ) {
        self.allImplementations = [.custom(custom)]
        self.implementations = allImplementations
    }
    
    /// Creates a password based authentication method.
    /// - Parameters:
    ///   - username: The username to authenticate with.
    ///   - password: The password to authenticate with.
    /// - Returns: A new SSH authentication method.
    public static func passwordBased(username: String, password: String) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(username: username, offer: .password(.init(password: password)))
    }
    
    /// Creates a public key based authentication method using RSA.
    /// - Parameters: 
    /// - username: The username to authenticate with.
    /// - privateKey: The RSA private key string (PEM or OpenSSH format) or an Insecure.RSA.PrivateKey object.
    /// - publicKey: Optional public key string. If not provided, will be derived from the private key.
    /// - passphrase: Optional passphrase for encrypted keys.
    /// - Returns: An SSH authentication method.
    public static func rsa(
        username: String, 
        privateKey: Any, 
        publicKey: String? = nil, 
        passphrase: String? = nil
    ) throws -> SSHAuthenticationMethod {
        let rsaKey: Insecure.RSA.PrivateKey
        
        if let keyString = privateKey as? String {
            do {
                // 处理字符串形式的密钥（自动检测 PEM 或 OpenSSH 格式）
                rsaKey = try Insecure.RSA.PrivateKey(
                    string: keyString, 
                    passphrase: passphrase
                )
            } catch {
                throw error
            }
        } else if let key = privateKey as? Insecure.RSA.PrivateKey {
            // 使用已存在的 RSA 私钥对象
            rsaKey = key
        } else {
            throw SSHClientError.invalidPrivateKeyType
        }
        
        return SSHAuthenticationMethod(username: username, offer: .privateKey(.init(privateKey: .init(custom: rsaKey))))
    }
    
    /// Backward compatibility method for PEM format
    /// @deprecated Use rsa(username:keyString:passphrase:) instead
    @available(*, deprecated, message: "Use rsa(username:privateKey:publicKey:passphrase:) instead")
    public static func rsaFromPEM(username: String, pemKey: String, passphrase: String? = nil) throws -> SSHAuthenticationMethod {
        return try rsa(username: username, privateKey: pemKey, passphrase: passphrase)
    }
    
    /// Creates a public key based authentication method.
    /// - Parameters: 
    /// - username: The username to authenticate with.
    /// - privateKey: The private key to authenticate with.
    public static func ed25519(username: String, privateKey: Curve25519.Signing.PrivateKey) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(username: username, offer: .privateKey(.init(privateKey: .init(ed25519Key: privateKey))))
    }
    
    /// Creates a public key based authentication method.
    /// - Parameters: 
    /// - username: The username to authenticate with.
    /// - privateKey: The private key to authenticate with.
    public static func p256(username: String, privateKey: P256.Signing.PrivateKey) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(username: username, offer: .privateKey(.init(privateKey: .init(p256Key: privateKey))))
    }
    
    /// Creates a public key based authentication method.
    /// - Parameters: 
    /// - username: The username to authenticate with.
    /// - privateKey: The private key to authenticate with.
    public static func p384(username: String, privateKey: P384.Signing.PrivateKey) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(username: username, offer: .privateKey(.init(privateKey: .init(p384Key: privateKey))))
    }
    
    /// Creates a public key based authentication method.
    /// - Parameters: 
    /// - username: The username to authenticate with.
    /// - privateKey: The private key to authenticate with.
    public static func p521(username: String, privateKey: P521.Signing.PrivateKey) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(username: username, offer: .privateKey(.init(privateKey: .init(p521Key: privateKey))))
    }
    
    public static func custom(_ auth: NIOSSHClientUserAuthenticationDelegate) -> SSHAuthenticationMethod {
        return SSHAuthenticationMethod(custom: auth)
    }
    
    public func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    ) {
        if implementations.isEmpty {
            nextChallengePromise.fail(SSHClientError.allAuthenticationOptionsFailed)
            return
        }
        
        let implementation = implementations.removeFirst()

        switch implementation {
        case .user(let username, offer: let offer):
            switch offer {
            case .password:
                guard availableMethods.contains(.password) else {
                    nextChallengePromise.fail(SSHClientError.unsupportedPasswordAuthentication)
                    return
                }
            case .hostBased:
                guard availableMethods.contains(.hostBased) else {
                    nextChallengePromise.fail(SSHClientError.unsupportedHostBasedAuthentication)
                    return
                }
            case .privateKey:
                guard availableMethods.contains(.publicKey) else {
                    nextChallengePromise.fail(SSHClientError.unsupportedPrivateKeyAuthentication)
                    return
                }
            case .none:
                ()
            }
            
            nextChallengePromise.succeed(NIOSSHUserAuthenticationOffer(username: username, serviceName: "", offer: offer))
        case .custom(let implementation):
            implementation.nextAuthenticationType(availableMethods: availableMethods, nextChallengePromise: nextChallengePromise)
        }
    }
}
