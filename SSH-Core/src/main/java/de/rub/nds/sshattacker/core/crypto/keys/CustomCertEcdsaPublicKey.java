/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.keys;

import de.rub.nds.sshattacker.core.constants.EcPointFormat;
import de.rub.nds.sshattacker.core.constants.NamedEcGroup;
import de.rub.nds.sshattacker.core.crypto.ec.Point;
import de.rub.nds.sshattacker.core.crypto.ec.PointFormatter;
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

/** A serializable ECDSA public key used in ECDSA certificates (SSH-ECDSA-CERT). */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class CustomCertEcdsaPublicKey extends CustomPublicKey implements ECPublicKey {

    // Fields for ECDSA specific parameters
    private Point publicKey; // Public key as Point
    private NamedEcGroup group;
    private BigInteger x;
    private BigInteger y;
    private String curveName;

    // New field for serial number in ECDSA certificates
    private long serial;

    // New field for the signature in ECDSA certificates
    private byte[] signature;
    private byte[] signatureKey;

    // New fields for certificate-specific information
    private String certType;
    private String certformat;
    private String keyId;
    private String reserved;
    private String[] validPrincipals;
    private byte[] nonce;
    private long validAfter;
    private long validBefore;

    private Map<String, String> criticalOptions; // Map to hold critical options as key-value pairs
    private Map<String, String> extensions; // Map to hold extensions as key-value pairs

    public CustomCertEcdsaPublicKey() {
        super();
    }

    public CustomCertEcdsaPublicKey(ECPublicKey publicKey) {
        super();
        this.x = publicKey.getW().getAffineX();
        this.y = publicKey.getW().getAffineY();
        this.curveName =
                publicKey
                        .getParams()
                        .getCurve()
                        .toString(); // Simplified, should be set based on curve name
    }

    public CustomCertEcdsaPublicKey(
            BigInteger x, BigInteger y, String curveName, NamedEcGroup group) {
        super();
        this.x = x;
        this.y = y;
        this.curveName = curveName;
        this.group = group;
    }

    // Getter for the public key point (W)
    @Override
    public ECPoint getW() {
        return new ECPoint(x, y);
    }

    // Setter for the public key as a Point object
    public void setPublicKey(Point w) {
        this.publicKey = w;
        this.x = w.getFieldX().getData();
        this.y = w.getFieldY().getData();
    }

    // Getter for the public key as a Point (getWAsPoint)
    public Point getWAsPoint() {
        return publicKey;
    }

    public void setCertFormat(String certformat) {
        this.certformat = certformat;
    }

    public String getCertFormat() {
        return certformat;
    }

    // Getter und setter for the curve name
    public String getCurveName() {
        return curveName;
    }

    public void setCurveName(String curveName) {
        this.curveName = curveName;
    }

    // Getter and setter for NamedEcGroup
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

    // Getter and setter for signature
    public byte[] getSignature() {
        return signature;
    }

    public void setSignature(byte[] signature) {
        this.signature = signature;
    }

    // Getter and setter for signature key
    public byte[] getSignatureKey() {
        return signatureKey;
    }

    public void setSignatureKey(byte[] signatureKey) {
        this.signatureKey = signatureKey;
    }

    // Getter and setter for certificate type
    public String getCertType() {
        return certType;
    }

    public void setCertType(String certType) {
        this.certType = certType;
    }

    // Getter and setter for key ID
    public String getKeyId() {
        return keyId;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    // Getter and setter for valid principals
    public String[] getValidPrincipals() {
        return validPrincipals;
    }

    public void setValidPrincipals(String[] validPrincipals) {
        this.validPrincipals = validPrincipals;
    }

    // Getter and setter for nonce
    public byte[] getNonce() {
        return nonce;
    }

    public void setNonce(byte[] nonce) {
        this.nonce = nonce;
    }

    // Getter and setter for validity periods
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

    public String getReserved() {
        return reserved;
    }

    public void setReserved(String reserved) {
        this.reserved = reserved;
    }

    // Getter and setter for critical options
    public Map<String, String> getCriticalOptions() {
        return criticalOptions;
    }

    public void setCriticalOptions(Map<String, String> criticalOptions) {
        this.criticalOptions = criticalOptions;
    }

    // Getter and setter for extensions
    public Map<String, String> getExtensions() {
        return extensions;
    }

    public void setExtensions(Map<String, String> extensions) {
        this.extensions = extensions;
    }

    // Return the ECDSA algorithm name
    @Override
    public String getAlgorithm() {
        return "EC";
    }

    // Encode public key
    @Override
    public byte[] getEncoded() {
        return PointFormatter.formatToByteArray(group, publicKey, EcPointFormat.UNCOMPRESSED);
    }

    // Implement the getParams method from ECPublicKey
    @Override
    public ECParameterSpec getParams() {
        try {
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec(group.getJavaName()));
            return parameters.getParameterSpec(ECParameterSpec.class);
        } catch (NoSuchAlgorithmException | InvalidParameterSpecException ex) {
            throw new UnsupportedOperationException("Could not generate ECParameterSpec", ex);
        }
    }
}
