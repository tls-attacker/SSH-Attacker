/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.keys;

import java.math.BigInteger;
import java.security.interfaces.DSAPublicKey;
import java.util.HashMap;
import java.util.Map;

/** A serializable DSA public key used in X.509 certificates (X509-SSH-DSA). */
public class CustomX509DsaPublicKey extends CustomDsaPublicKey {

    // X.509-specific fields
    private String issuer; // Issuer Distinguished Name
    private String subject; // Subject Distinguished Name
    private String publicKeyAlgorithm;
    private int version;
    private long serial; // Certificate serial number
    private String signatureAlgorithm; // Signature algorithm
    private byte[] signature; // Certificate signature
    private byte[] subjectKeyIdentifier; // Subject Key Identifier

    // Validity period
    private long validAfter; // Not Before (valid after)
    private long validBefore; // Not After (valid before)

    // Extensions (if any)
    private HashMap<String, String> extensions; // Extensions (optional)

    public CustomX509DsaPublicKey() {
        super();
    }

    public CustomX509DsaPublicKey(DSAPublicKey publicKey, byte[] signature) {
        super(publicKey);
        if (signature == null || signature.length == 0) {
            throw new IllegalArgumentException("Signature cannot be null or empty");
        }
        this.signature = signature;
    }

    public CustomX509DsaPublicKey(
            BigInteger p, BigInteger q, BigInteger g, BigInteger y, byte[] signature) {
        super(p, q, g, y);
        if (signature == null || signature.length == 0) {
            throw new IllegalArgumentException("Signature cannot be null or empty");
        }
        this.signature = signature;
    }

    public CustomX509DsaPublicKey(CustomX509DsaPublicKey other) {
        super(other);
        issuer = other.issuer;
        subject = other.subject;
        publicKeyAlgorithm = other.publicKeyAlgorithm;
        version = other.version;
        serial = other.serial;
        signatureAlgorithm = other.signatureAlgorithm;
        signature = other.signature != null ? other.signature.clone() : null;
        subjectKeyIdentifier =
                other.subjectKeyIdentifier != null ? other.subjectKeyIdentifier.clone() : null;
        validAfter = other.validAfter;
        validBefore = other.validBefore;
        extensions = other.extensions != null ? new HashMap<>(other.extensions) : null;
    }

    @Override
    public CustomX509DsaPublicKey createCopy() {
        return new CustomX509DsaPublicKey(this);
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

    public void setExtensions(HashMap<String, String> extensions) {
        this.extensions = extensions;
    }

    // Getter and setter for Subject Key Identifier
    public byte[] getSubjectKeyIdentifier() {
        return subjectKeyIdentifier;
    }

    public void setSubjectKeyIdentifier(byte[] subjectKeyIdentifier) {
        this.subjectKeyIdentifier = subjectKeyIdentifier;
    }
}
