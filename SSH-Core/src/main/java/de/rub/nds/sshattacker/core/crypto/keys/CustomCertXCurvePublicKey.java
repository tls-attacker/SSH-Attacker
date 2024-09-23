/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
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
 * A serializable ED25519/ED448 certificate public key used in certificates (SSH-ED25519-CERT).
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class CustomCertXCurvePublicKey extends CustomPublicKey {

    private NamedEcGroup group;
    private byte[] publicKey;

    // New fields for certificate-specific information
    private long serial;
    private String certType;
    private String keyId;
    private String[] validPrincipals;
    private byte[] nonce;
    private long validAfter;
    private long validBefore;
    private byte[] signature;
    private byte[] signatureKey;
    private Map<String, String> criticalOptions;
    private Map<String, String> extensions;

    public CustomCertXCurvePublicKey() {
        super();
    }

    public CustomCertXCurvePublicKey(byte[] publicKey, NamedEcGroup group) {
        super();
        this.publicKey = publicKey;
        this.group = group;
    }

    // Implementing the getAlgorithm() method as required by the Key interface
    @Override
    public String getAlgorithm() {
        return "ED25519";
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

    // Getter and setter for validAfter
    public long getValidAfter() {
        return validAfter;
    }

    public void setValidAfter(long validAfter) {
        this.validAfter = validAfter;
    }

    // Getter and setter for validBefore
    public long getValidBefore() {
        return validBefore;
    }

    public void setValidBefore(long validBefore) {
        this.validBefore = validBefore;
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

}
