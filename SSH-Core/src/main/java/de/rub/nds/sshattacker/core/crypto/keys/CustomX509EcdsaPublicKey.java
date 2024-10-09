package de.rub.nds.sshattacker.core.crypto.keys;

import de.rub.nds.sshattacker.core.constants.NamedEcGroup;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.InvalidParameterSpecException;
import java.util.Map;

/** A serializable ECDSA public key used in X.509 certificates (X509-SSH-ECDSA). */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class CustomX509EcdsaPublicKey extends CustomPublicKey implements ECPublicKey {

    // ECDSA-specific fields
    private BigInteger x;
    private BigInteger y;
    private String curveName;

    // New field for the named EC group
    private NamedEcGroup group;

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

    public CustomX509EcdsaPublicKey() {
        super();
    }

    public CustomX509EcdsaPublicKey(ECPublicKey publicKey, byte[] signature, String curveName, NamedEcGroup group) {
        super();
        if (signature == null || signature.length == 0) {
            throw new IllegalArgumentException("Signature cannot be null or empty");
        }
        this.x = publicKey.getW().getAffineX();
        this.y = publicKey.getW().getAffineY();
        this.curveName = curveName;
        this.signature = signature;
        this.group = group;  // Set the group
    }

    public CustomX509EcdsaPublicKey(BigInteger x, BigInteger y, byte[] signature, String curveName, NamedEcGroup group) {
        super();
        if (signature == null || signature.length == 0) {
            throw new IllegalArgumentException("Signature cannot be null or empty");
        }
        this.x = x;
        this.y = y;
        this.signature = signature;
        this.curveName = curveName;
        this.group = group;  // Set the group
    }

    // Getter for the public key point (W)
    @Override
    public ECPoint getW() {
        return new ECPoint(x, y);
    }

    // Setter for the public key point
    public void setPublicKey(ECPoint w) {
        this.x = w.getAffineX();
        this.y = w.getAffineY();
    }

    // Getters and setters for ECDSA public key fields
    public BigInteger getX() {
        return x;
    }

    public void setX(BigInteger x) {
        this.x = x;
    }

    public BigInteger getY() {
        return y;
    }

    public void setY(BigInteger y) {
        this.y = y;
    }

    public String getCurveName() {
        return curveName;
    }

    public void setCurveName(String curveName) {
        this.curveName = curveName;
    }

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

    // Return the ECDSA algorithm name
    @Override
    public String getAlgorithm() {
        return "EC";
    }

    // Implement the getParams method from ECPublicKey
    @Override
    public ECParameterSpec getParams() {
        try {
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec(group.getJavaName()));  // Use the group to retrieve the curve name
            return parameters.getParameterSpec(ECParameterSpec.class);
        } catch (NoSuchAlgorithmException | InvalidParameterSpecException ex) {
            throw new UnsupportedOperationException("Fehler beim Generieren von ECParameterSpec", ex);
        }
    }
}