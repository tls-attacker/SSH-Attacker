/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.keys;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.math.BigInteger;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.util.Map;

/** A serializable DSA public key used in DSA certificates (SSH-DSA-CERT). */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class CustomCertDsaPublicKey extends CustomPublicKey implements DSAPublicKey {

    private BigInteger p;
    private BigInteger q;
    private BigInteger g;
    private BigInteger y;

    // New field for serial number in DSA certificates
    private long serial;

    // New field for the signature in DSA certificates
    private byte[] signature;
    private byte[] signatureKey;

    // New fields for certificate-specific information
    private String certType;
    private String keyId;
    private String reserved;
    private String[] validPrincipals;
    private byte[] nonce;
    private long validAfter;
    private long validBefore;

    private Map<String, String> criticalOptions;  // Map to hold critical options as key-value pairs
    private Map<String, String> extensions;       // Map to hold extensions as key-value pairs

    public CustomCertDsaPublicKey() {
        super();
    }

    public CustomCertDsaPublicKey(DSAPublicKey publicKey) {
        super();
        p = publicKey.getParams().getP();
        q = publicKey.getParams().getQ();
        g = publicKey.getParams().getG();
        y = publicKey.getY();
    }

    public CustomCertDsaPublicKey(BigInteger p, BigInteger q, BigInteger g, BigInteger y) {
        super();
        this.p = p;
        this.q = q;
        this.g = g;
        this.y = y;
    }

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

    public String getReserved() {
        return reserved;
    }

    public void setReserved(String reserved) {
        this.reserved = reserved;
    }

    public void setExtensions(Map<String, String> extensions) {
        this.extensions = extensions;
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
