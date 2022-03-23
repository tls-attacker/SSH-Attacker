/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.keys;

import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

/** A serializable RSA private key used in RSA encryption and signatures. */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class CustomRsaPrivateKey extends CustomPrivateKey implements RSAPrivateKey {

    private BigInteger modulus;
    private BigInteger privateExponent;

    @SuppressWarnings("unused")
    private CustomRsaPrivateKey() {}

    public CustomRsaPrivateKey(BigInteger privateExponent, BigInteger modulus) {
        this.modulus = modulus;
        this.privateExponent = privateExponent;
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
