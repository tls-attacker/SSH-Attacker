/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.keys;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;

/** A serializable RSA public key used in RSA certificates (SSH-RSA-CERT). */
public class CustomCertRsaPublicKey extends CustomRsaPublicKey {

    // New field for serial number in RSA certificates
    private long serial;

    // New field for the signature in RSA certificates
    private byte[] signature;
    private byte[] signatureKey;

    // New fields for certificate-specific information
    private String certformat;
    private String certType;
    private String keyId;
    private String reserved;
    private String[] validPrincipals;
    private byte[] nonce;
    private long validAfter;
    private long validBefore;

    private HashMap<String, String> extensions; // Map to hold extensions as key-value pairs
    private HashMap<String, String>
            criticalOptions; // Map to hold critical options as key-value pairs

    public CustomCertRsaPublicKey() {
        super();
    }

    public CustomCertRsaPublicKey(RSAPublicKey publicKey) {
        super(publicKey);
    }

    public CustomCertRsaPublicKey(BigInteger publicExponent, BigInteger modulus) {
        super(publicExponent, modulus);
    }

    public CustomCertRsaPublicKey(CustomCertRsaPublicKey other) {
        super(other);
        serial = other.serial;
        signature = other.signature != null ? other.signature.clone() : null;
        signatureKey = other.signatureKey != null ? other.signatureKey.clone() : null;
        certformat = other.certformat;
        certType = other.certType;
        keyId = other.keyId;
        reserved = other.reserved;
        validPrincipals = other.validPrincipals != null ? other.validPrincipals.clone() : null;
        nonce = other.nonce != null ? other.nonce.clone() : null;
        validAfter = other.validAfter;
        validBefore = other.validBefore;
        extensions = other.extensions != null ? new HashMap<>(other.extensions) : null;
        criticalOptions =
                other.criticalOptions != null ? new HashMap<>(other.criticalOptions) : null;
    }

    @Override
    public CustomCertRsaPublicKey createCopy() {
        return new CustomCertRsaPublicKey(this);
    }

    public void setCertFormat(String certformat) {
        this.certformat = certformat;
    }

    public String getCertFormat() {
        return certformat;
    }

    public long getSerial() {
        return serial;
    }

    public void setSerial(long serial) {
        this.serial = serial;
    }

    public byte[] getSignature() {
        return signature;
    }

    public void setSignature(byte[] signature) {
        this.signature = signature;
    }

    public String getCertType() {
        return certType;
    }

    public void setCertType(String certType) {
        this.certType = certType;
    }

    public byte[] getNonce() {
        return nonce;
    }

    public void setNonce(byte[] nonce) {
        this.nonce = nonce;
    }

    public String getKeyId() {
        return keyId;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    public String[] getValidPrincipals() {
        return validPrincipals;
    }

    public void setValidPrincipals(String[] validPrincipals) {
        this.validPrincipals = validPrincipals;
    }

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

    public byte[] getSignatureKey() {
        return signatureKey;
    }

    public void setSignatureKey(byte[] signatureKey) {
        this.signatureKey = signatureKey;
    }

    public String getReserved() {
        return reserved;
    }

    public void setReserved(String reserved) {
        this.reserved = reserved;
    }

    public Map<String, String> getExtensions() {
        return extensions;
    }

    public void setExtensions(HashMap<String, String> extensions) {
        this.extensions = extensions;
    }

    public Map<String, String> getCriticalOptions() {
        return criticalOptions;
    }

    public void setCriticalOptions(HashMap<String, String> criticalOptions) {
        this.criticalOptions = criticalOptions;
    }
}
