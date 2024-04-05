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
import java.security.interfaces.RSAPublicKey;
import java.util.Objects;

/** A serializable RSA public key used in RSA encryption and signatures. */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class CustomRsaPublicKey extends CustomPublicKey implements RSAPublicKey {

    private BigInteger modulus;
    private BigInteger publicExponent;

    public CustomRsaPublicKey() {
        super();
    }

    public CustomRsaPublicKey(RSAPublicKey publicKey) {
        super();
        modulus = publicKey.getModulus();
        publicExponent = publicKey.getPublicExponent();
    }

    public CustomRsaPublicKey(BigInteger publicExponent, BigInteger modulus) {
        super();
        this.modulus = modulus;
        this.publicExponent = publicExponent;
    }

    @Override
    public BigInteger getModulus() {
        return modulus;
    }

    public void setModulus(BigInteger modulus) {
        this.modulus = modulus;
    }

    @Override
    public BigInteger getPublicExponent() {
        return publicExponent;
    }

    public void setPublicExponent(BigInteger publicExponent) {
        this.publicExponent = publicExponent;
    }

    // Interface methods
    @Override
    public String getAlgorithm() {
        return "RSA";
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CustomRsaPublicKey that = (CustomRsaPublicKey) o;
        return Objects.equals(modulus, that.modulus)
                && Objects.equals(publicExponent, that.publicExponent);
    }

    @Override
    public int hashCode() {
        return Objects.hash(modulus, publicExponent);
    }
}
