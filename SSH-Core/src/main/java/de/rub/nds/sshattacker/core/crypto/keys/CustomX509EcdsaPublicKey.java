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
import de.rub.nds.sshattacker.core.crypto.keys.serializer.X509EcdsaPublicKeySerializer;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.util.HashMap;
import java.util.Map;

/** A serializable ECDSA public key used in X.509 certificates (X509-SSH-ECDSA). */
public class CustomX509EcdsaPublicKey extends CustomEcPublicKey {

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

    public CustomX509EcdsaPublicKey() {
        super();
    }

    public CustomX509EcdsaPublicKey(Point publicKey, NamedEcGroup group, byte[] signature) {
        super(publicKey, group);
        if (signature == null || signature.length == 0) {
            throw new IllegalArgumentException("Signature cannot be null or empty");
        }
        this.signature = signature;
    }

    public CustomX509EcdsaPublicKey(ECPublicKey publicKey, byte[] signature)
            throws CryptoException {
        super(publicKey);
        if (signature == null || signature.length == 0) {
            throw new IllegalArgumentException("Signature cannot be null or empty");
        }
        this.signature = signature;
    }

    public CustomX509EcdsaPublicKey(
            BigInteger x, BigInteger y, NamedEcGroup group, byte[] signature) {
        super(x, y, group);
        if (signature == null || signature.length == 0) {
            throw new IllegalArgumentException("Signature cannot be null or empty");
        }
        this.signature = signature;
    }

    public CustomX509EcdsaPublicKey(CustomX509EcdsaPublicKey other) {
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
    public CustomX509EcdsaPublicKey createCopy() {
        return new CustomX509EcdsaPublicKey(this);
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

    public static final X509EcdsaPublicKeySerializer SERIALIZER =
            new X509EcdsaPublicKeySerializer();

    @Override
    public byte[] serialize() {
        return SERIALIZER.serialize(this);
    }
}
