/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.keys;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;

/** A serializable RSA private key used in RSA encryption and signatures. */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class CustomRsaPrivateKey extends CustomPrivateKey implements RSAPrivateKey {

    private BigInteger modulus;
    private BigInteger privateExponent;

    public CustomRsaPrivateKey() {
        super();
    }

    public CustomRsaPrivateKey(RSAPrivateKey privateKey) {
        super();
        modulus = privateKey.getModulus();
        privateExponent = privateKey.getPrivateExponent();
    }

    public CustomRsaPrivateKey(BigInteger privateExponent, BigInteger modulus) {
        super();
        this.modulus = modulus;
        this.privateExponent = privateExponent;
    }

    public CustomRsaPrivateKey(CustomRsaPrivateKey other) {
        super(other);
        modulus = other.modulus;
        privateExponent = other.privateExponent;
    }

    @Override
    public CustomRsaPrivateKey createCopy() {
        return new CustomRsaPrivateKey(this);
    }

    @Override
    public BigInteger getModulus() {
        return modulus;
    }

    public void setModulus(BigInteger modulus) {
        this.modulus = modulus;
    }

    @Override
    public BigInteger getPrivateExponent() {
        return privateExponent;
    }

    public void setPrivateExponent(BigInteger privateExponent) {
        this.privateExponent = privateExponent;
    }

    // Interface methods
    @Override
    public String getAlgorithm() {
        return "RSA";
    }
}
