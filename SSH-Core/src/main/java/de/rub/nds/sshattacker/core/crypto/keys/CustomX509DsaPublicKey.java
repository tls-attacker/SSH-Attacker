package de.rub.nds.sshattacker.core.crypto.keys;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.math.BigInteger;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.util.Map;

/** A serializable DSA public key used in X.509 certificates (X509-SSH-DSA). */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class CustomX509DsaPublicKey extends CustomPublicKey implements DSAPublicKey {

    // DSA-specific fields
    private BigInteger p;
    private BigInteger q;
    private BigInteger g;
    private BigInteger y;

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

    public CustomX509DsaPublicKey() {
        super();
    }

    public CustomX509DsaPublicKey(DSAPublicKey publicKey, byte[] signature) {
        super();
        if (signature == null || signature.length == 0) {
            throw new IllegalArgumentException("Signature cannot be null or empty");
        }
        this.p = publicKey.getParams().getP();
        this.q = publicKey.getParams().getQ();
        this.g = publicKey.getParams().getG();
        this.y = publicKey.getY();
        this.signature = signature;
    }

    public CustomX509DsaPublicKey(BigInteger p, BigInteger q, BigInteger g, BigInteger y, byte[] signature) {
        super();
        if (signature == null || signature.length == 0) {
            throw new IllegalArgumentException("Signature cannot be null or empty");
        }
        this.p = p;
        this.q = q;
        this.g = g;
        this.y = y;
        this.signature = signature;
    }

    // Getters and setters for DSA public key fields
    @Override
    public BigInteger getY() {
        return y;
    }

    public void setY(BigInteger y) {
        this.y = y;
    }

    public BigInteger getP() {
        return p;
    }

    public void setP(BigInteger p) {
        this.p = p;
    }

    public BigInteger getQ() {
        return q;
    }

    public void setQ(BigInteger q) {
        this.q = q;
    }

    public BigInteger getG() {
        return g;
    }

    public void setG(BigInteger g) {
        this.g = g;
    }

    // Getter and setter for serial number
    public long getSerial() {
        return serial;
    }

    public void setSerial(long serial) {
        this.serial = serial;
    }

    // Getters and setters for the signature and algorithm
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

    // Return the DSA algorithm name
    @Override
    public String getAlgorithm() {
        return "DSA";
    }

    // Implement the getParams method from DSAPublicKey
    @Override
    public DSAParams getParams() {
        return new DSAParams() {
            @Override
            public BigInteger getP() {
                return p;
            }

            @Override
            public BigInteger getQ() {
                return q;
            }

            @Override
            public BigInteger getG() {
                return g;
            }
        };
    }
}
