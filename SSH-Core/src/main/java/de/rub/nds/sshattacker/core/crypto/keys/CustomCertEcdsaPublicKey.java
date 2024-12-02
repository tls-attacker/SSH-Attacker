/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.keys;

import de.rub.nds.sshattacker.core.constants.NamedEcGroup;
import de.rub.nds.sshattacker.core.crypto.ec.Point;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.util.HashMap;
import java.util.Map;

/** A serializable ECDSA public key used in ECDSA certificates (SSH-ECDSA-CERT). */
public class CustomCertEcdsaPublicKey extends CustomEcPublicKey {

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

    private HashMap<String, String>
            criticalOptions; // Map to hold critical options as key-value pairs
    private HashMap<String, String> extensions; // Map to hold extensions as key-value pairs

    public CustomCertEcdsaPublicKey() {
        super();
    }

    public CustomCertEcdsaPublicKey(Point publicKey, NamedEcGroup group) {
        super(publicKey, group);
    }

    public CustomCertEcdsaPublicKey(ECPublicKey publicKey) throws CryptoException {
        super(publicKey);
    }

    public CustomCertEcdsaPublicKey(BigInteger x, BigInteger y, NamedEcGroup group) {
        super(x, y, group);
    }

    public CustomCertEcdsaPublicKey(CustomCertEcdsaPublicKey other) {
        super(other);
        serial = other.serial;
        signature = other.signature != null ? other.signature.clone() : null;
        signatureKey = other.signatureKey != null ? other.signatureKey.clone() : null;
        certType = other.certType;
        certformat = other.certformat;
        keyId = other.keyId;
        reserved = other.reserved;
        validPrincipals = other.validPrincipals != null ? other.validPrincipals.clone() : null;
        nonce = other.nonce != null ? other.nonce.clone() : null;
        validAfter = other.validAfter;
        validBefore = other.validBefore;
        criticalOptions =
                other.criticalOptions != null ? new HashMap<>(other.criticalOptions) : null;
        extensions = other.extensions != null ? new HashMap<>(other.extensions) : null;
    }

    @Override
    public CustomCertEcdsaPublicKey createCopy() {
        return new CustomCertEcdsaPublicKey(this);
    }

    public void setCertFormat(String certformat) {
        this.certformat = certformat;
    }

    public String getCertFormat() {
        return certformat;
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

    public void setCriticalOptions(HashMap<String, String> criticalOptions) {
        this.criticalOptions = criticalOptions;
    }

    // Getter and setter for extensions
    public Map<String, String> getExtensions() {
        return extensions;
    }

    public void setExtensions(HashMap<String, String> extensions) {
        this.extensions = extensions;
    }
}
