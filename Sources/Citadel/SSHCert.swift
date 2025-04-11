import CCryptoBoringSSL
import BigInt
import Foundation
import Crypto
import NIO
import NIOSSH

public struct InvalidOpenSSHKey: Error {
    public enum UnsupportedFeature: String {
        case multipleKeys, unsupportedPublicKeyType, unsupportedKDF, unsupportedCipher
    }

    let reason: String

    static let invalidUTF8String = InvalidOpenSSHKey(reason: "invalidUTF8String")
    static let missingPublicKeyBuffer = InvalidOpenSSHKey(reason: "missingPublicKeyBuffer")
    static let missingPrivateKeyBuffer = InvalidOpenSSHKey(reason: "missingPrivateKeyBuffer")
    static let missingPublicKeyInPrivateKey = InvalidOpenSSHKey(reason: "missingPublicKeyInPrivateKey")
    static let missingComment = InvalidOpenSSHKey(reason: "missingComment")
    static let invalidCheck = InvalidOpenSSHKey(reason: "invalidCheck")
    static let invalidPublicKeyInPrivateKey = InvalidOpenSSHKey(reason: "invalidPublicKeyInPrivateKey")
    static let invalidLayout = InvalidOpenSSHKey(reason: "invalidLayout")
    static let invalidPadding = InvalidOpenSSHKey(reason: "invalidPadding")
    static let invalidOpenSSHBoundary = InvalidOpenSSHKey(reason: "invalidOpenSSHBoundary")
    static let invalidBase64Payload = InvalidOpenSSHKey(reason: "invalidBase64Payload")
    static let invalidOpenSSHPrefix = InvalidOpenSSHKey(reason: "invalidOpenSSHPrefix")
    static func unsupportedFeature(_ feature: UnsupportedFeature) -> InvalidOpenSSHKey {
        InvalidOpenSSHKey(reason: "UnsupportedFeature: \(feature.rawValue)")
    }
    static let invalidPublicKeyPrefix = InvalidOpenSSHKey(reason: "invalidPublicKeyPrefix")
    static let invalidOrUnsupportedBCryptConfig = InvalidOpenSSHKey(reason: "invalidOrUnsupportedBCryptConfig")
    static let unexpectedKDFNoneOptions = InvalidOpenSSHKey(reason: "unexpectedKDFNoneOptions")
}

public typealias InvalidKey = InvalidOpenSSHKey

extension Curve25519.Signing.PublicKey: ByteBufferConvertible {
    static func read(consuming buffer: inout ByteBuffer) throws -> Curve25519.Signing.PublicKey {
        guard var publicKeyBuffer = buffer.readSSHBuffer() else {
            throw InvalidOpenSSHKey.missingPublicKeyBuffer
        }
        
        return try self.init(rawRepresentation: publicKeyBuffer.readBytes(length: publicKeyBuffer.readableBytes)!)
    }
    
    @discardableResult
    func write(to buffer: inout ByteBuffer) -> Int {
        buffer.writeData(self.rawRepresentation)
    }
}

extension Curve25519.Signing.PrivateKey: OpenSSHPrivateKey {
    typealias PublicKey = Curve25519.Signing.PublicKey
    static var publicKeyPrefix: String { "ssh-ed25519" }
    static var privateKeyPrefix: String { "ssh-ed25519" }
    static var keyType: OpenSSH.KeyType { .sshED25519 }
    
    /// Creates a new Curve25519 private key from an OpenSSH private key string.
    /// - Parameters:
    ///  - key: The OpenSSH private key string.
    /// - decryptionKey: The key to decrypt the private key with, if any.
    public init(sshEd25519 data: Data, decryptionKey: Data? = nil) throws {
        if let string = String(data: data, encoding: .utf8) {
            try self.init(sshEd25519: string, decryptionKey: decryptionKey)
        } else {
            throw InvalidOpenSSHKey.invalidUTF8String
        }
    }
    
    /// Creates a new Curve25519 private key from an OpenSSH private key string.
    /// - Parameters:
    ///  - key: The OpenSSH private key string.
    /// - decryptionKey: The key to decrypt the private key with, if any.
    public init(sshEd25519 key: String, decryptionKey: Data? = nil) throws {
        self = try OpenSSH.PrivateKey<Curve25519.Signing.PrivateKey>.init(string: key, decryptionKey: decryptionKey).privateKey
    }
}

extension Insecure.RSA.PublicKey: ByteBufferConvertible {
    func write(to buffer: inout ByteBuffer) {
        let _: Int = self.write(to: &buffer)
    }
}

extension Insecure.RSA.PrivateKey: OpenSSHPrivateKey {
    typealias PublicKey = Insecure.RSA.PublicKey
    
    static var publicKeyPrefix: String { "ssh-rsa" }
    static var privateKeyPrefix: String { "ssh-rsa" }
    static var keyType: OpenSSH.KeyType { .sshRSA }
    
    /// Creates a new RSA private key from a string representation.
    /// Automatically detects and handles both OpenSSH and PEM formats.
    /// - Parameters:
    ///  - key: The private key string (OpenSSH or PEM format).
    /// - decryptionKey: The key to decrypt the private key with, if using OpenSSH format.
    /// - passphrase: The passphrase to decrypt the private key with, if using PEM format.
    public convenience init(string key: String, decryptionKey: Data? = nil, passphrase: String? = nil) throws {
        // Check if it's a PEM formatted RSA private key
        if key.contains("-----BEGIN RSA PRIVATE KEY-----") {
            try self.init(fromPEM: key, passphrase: passphrase)
        } else if key.contains("-----BEGIN OPENSSH PRIVATE KEY-----") {
            try self.init(fromOpenSSH: key, decryptionKey: decryptionKey)
        } else {
            throw RSAError.invalidPem
        }
    }
    
    // 内部方法，从PEM格式初始化
    private convenience init(fromPEM pemKey: String, passphrase: String? = nil) throws {
        // Read the RSA key from PEM
        let rsaKey = try PEM.readPrivateKey(from: pemKey, passphrase: passphrase)
        defer {
            CCryptoBoringSSL_RSA_free(rsaKey)
        }
        
        // Extract components
        var n: UnsafePointer<BIGNUM>?
        var e: UnsafePointer<BIGNUM>?
        var d: UnsafePointer<BIGNUM>?
        CCryptoBoringSSL_RSA_get0_key(rsaKey, &n, &e, &d)
        
        guard let modulus = n, let publicExponent = e, let privateExponent = d else {
            throw RSAError.pkcs1Error
        }
        
        // Copy values to avoid memory issues
        let modulusCopy = CCryptoBoringSSL_BN_dup(modulus)!
        let publicExponentCopy = CCryptoBoringSSL_BN_dup(publicExponent)!
        let privateExponentCopy = CCryptoBoringSSL_BN_dup(privateExponent)!
        
        self.init(privateExponent: privateExponentCopy, publicExponent: publicExponentCopy, modulus: modulusCopy)
    }
    
    // 内部方法，从OpenSSH格式初始化
    private convenience init(fromOpenSSH key: String, decryptionKey: Data? = nil) throws {
        let privateKey = try OpenSSH.PrivateKey<Insecure.RSA.PrivateKey>.init(string: key, decryptionKey: decryptionKey).privateKey
        let publicKey = privateKey.publicKey as! Insecure.RSA.PublicKey
        
        // Copy, so that our values stored in `privateKey` aren't freed when exciting the initializers scope
        let modulus = CCryptoBoringSSL_BN_new()!
        let publicExponent = CCryptoBoringSSL_BN_new()!
        let privateExponent = CCryptoBoringSSL_BN_new()!
        
        CCryptoBoringSSL_BN_copy(modulus, publicKey.modulus)
        CCryptoBoringSSL_BN_copy(publicExponent, publicKey.publicExponent)
        CCryptoBoringSSL_BN_copy(privateExponent, privateKey.privateExponent)
        
        self.init(privateExponent: privateExponent, publicExponent: publicExponent, modulus: modulus)
    }
    
    /// 保持兼容原有API的初始化方法
    public convenience init(sshRsa data: Data, decryptionKey: Data? = nil) throws {
        if let string = String(data: data, encoding: .utf8) {
            try self.init(string: string, decryptionKey: decryptionKey)
        } else {
            throw InvalidOpenSSHKey.invalidUTF8String
        }
    }
    
    /// 保持兼容原有API的初始化方法，内部调用统一处理方法
    public convenience init(sshRsa key: String, decryptionKey: Data? = nil) throws {
        try self.init(string: key, decryptionKey: decryptionKey)
    }
    
    /// 为了完整性保留的内部方法，但推荐使用统一的init(string:)方法
    @available(*, deprecated, message: "Use init(string:passphrase:) instead")
    public convenience init(pemRsa pemKey: String, passphrase: String? = nil) throws {
        try self.init(string: pemKey, passphrase: passphrase)
    }
}
