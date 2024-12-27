/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.keys;

import de.rub.nds.sshattacker.core.crypto.keys.serializer.RsaPublicKeySerializer;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;

/** A serializable RSA public key used in RSA encryption and signatures. */
@XmlRootElement
public class CustomRsaPublicKey extends CustomPublicKey implements RSAPublicKey {

    protected BigInteger modulus;
    protected BigInteger publicExponent;

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

    public CustomRsaPublicKey(CustomRsaPublicKey other) {
        super(other);
        modulus = other.modulus;
        publicExponent = other.publicExponent;
    }

    @Override
    public CustomRsaPublicKey createCopy() {
        return new CustomRsaPublicKey(this);
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

    public static final RsaPublicKeySerializer SERIALIZER = new RsaPublicKeySerializer();

    @Override
    public byte[] serialize() {
        return SERIALIZER.serialize(this);
    }
}
