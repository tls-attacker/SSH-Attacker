package de.rub.nds.sshattacker.core.crypto.keys;

import de.rub.nds.sshattacker.core.constants.NamedEcGroup;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;

/**
 * A serializable ED25519/ED448 X.509 public key used in certificates (X509-SSH-Ed25519).
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class CustomX509XCurvePublicKey extends CustomPublicKey {

    private NamedEcGroup group; // Named group (Ed25519 or Ed448)
    private byte[] publicKey;   // Public key bytes

    // X.509-specific fields
    private String issuer;      // Issuer Distinguished Name
    private String subject;     // Subject Distinguished Name
    private String publicKeyAlgorithm;
    private int version;
    private long serial;        // Certificate serial number
    private String signatureAlgorithm;  // Signature algorithm
    private byte[] signature;   // Certificate signature
    private byte[] subjectKeyIdentifier; // Subject Key Identifier

    // Validity period
    private long validAfter;    // Not Before (valid after)
    private long validBefore;   // Not After (valid before)

    // Extensions (if any)
    private Map<String, String> extensions;  // Extensions (optional)

    public CustomX509XCurvePublicKey() {
        super();
    }

    public CustomX509XCurvePublicKey(byte[] publicKey, NamedEcGroup group, byte[] signature) {
        super();
        if (signature == null || signature.length == 0) {
            throw new IllegalArgumentException("Signature cannot be null or empty");
        }
        this.publicKey = publicKey;
        this.group = group;
        this.signature = signature;
    }

    // Getter and setter for public key
    public byte[] getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(byte[] publicKey) {
        this.publicKey = publicKey;
    }

    // Getter and setter for group
    public NamedEcGroup getGroup() {
        return group;
    }

    public void setGroup(NamedEcGroup group) {
        this.group = group;
    }

    // Getter and setter for serial number
    public long getSerial() {
        return serial;
    }

    public void setSerial(long serial) {
        this.serial = serial;
    }

    // Getter and setter for the signature and algorithm
    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public byte[] getSignature() {
        if (signature == null) {
            throw new IllegalStateException("Signature is not set in the publicKey");
        }
        return signature;
    }

    public int getVersion() {
        return version;
    }

    public void setVersion(int version) {
        this.version = version;
    }

    public void setSignature(byte[] signature) {
        if (signature == null || signature.length == 0) {
            throw new IllegalArgumentException("Signature cannot be null or empty");
        }
        this.signature = signature;
    }

    public String getPublicKeyAlgorithm() {
        return publicKeyAlgorithm;
    }

    public void setPublicKeyAlgorithm(String publicKeyAlgorithm) {
        this.publicKeyAlgorithm = publicKeyAlgorithm;
    }

    // Getters and setters for issuer and subject
    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    // Getters and setters for the validity period
    public long getValidAfter() {
        return validAfter;
    }

    public void setValidAfter(long validAfter) {
        this.validAfter = validAfter;
    }

    public long getValidBefore() {
        return validBefore;
    }

    public void setValidBefore(long validBefore) {
        this.validBefore = validBefore;
    }

    // Getters and setters for extensions (optional)
    public Map<String, String> getExtensions() {
        return extensions;
    }

    public void setExtensions(Map<String, String> extensions) {
        this.extensions = extensions;
    }

    // Getter and setter for Subject Key Identifier
    public byte[] getSubjectKeyIdentifier() {
        return subjectKeyIdentifier;
    }

    public void setSubjectKeyIdentifier(byte[] subjectKeyIdentifier) {
        this.subjectKeyIdentifier = subjectKeyIdentifier;
    }

    // Method to convert the public key to a PublicKey object (EdDSA key)
    public PublicKey toEdDsaKey() {
        try {
            KeyFactory keyFactory;
            SubjectPublicKeyInfo publicKeyInfo;
            if (group == NamedEcGroup.CURVE25519) {
                keyFactory = KeyFactory.getInstance("Ed25519");
                publicKeyInfo = new SubjectPublicKeyInfo(
                        new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519),
                        publicKey);
            } else if (group == NamedEcGroup.CURVE448) {
                keyFactory = KeyFactory.getInstance("Ed448");
                publicKeyInfo = new SubjectPublicKeyInfo(
                        new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed448),
                        publicKey);
            } else {
                throw new UnsupportedOperationException("Unsupported group: " + group);
            }
            X509EncodedKeySpec encodedKeySpec = new X509EncodedKeySpec(publicKeyInfo.getEncoded());
            return keyFactory.generatePublic(encodedKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
            throw new RuntimeException("Failed to convert certificate public key to EdDSA key", e);
        }
    }

    @Override
    public String getAlgorithm() {
        return "EdDSA";
    }
}
