/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.keys;

import de.rub.nds.sshattacker.core.constants.NamedDHGroup;
import java.math.BigInteger;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

/** A serializable diffie-hellman public key used in the DH key exchange. */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class CustomDhPublicKey extends CustomPublicKey implements DHPublicKey {

    // Group parameters
    private BigInteger modulus;
    private BigInteger generator;

    // Public key
    private BigInteger publicKey;

    @SuppressWarnings("unused")
    public CustomDhPublicKey() {}

    public CustomDhPublicKey(NamedDHGroup group, BigInteger publicKey) {
        this(group.getModulus(), group.getGenerator(), publicKey);
    }

    public CustomDhPublicKey(BigInteger modulus, BigInteger generator, BigInteger publicKey) {
        this.modulus = modulus;
        this.generator = generator;
        this.publicKey = publicKey;
    }

    public BigInteger getModulus() {
        return modulus;
    }

    public void setModulus(BigInteger modulus) {
        this.modulus = modulus;
    }

    public BigInteger getGenerator() {
        return generator;
    }

    public void setGenerator(BigInteger generator) {
        this.generator = generator;
    }

    public BigInteger getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(BigInteger publicKey) {
        this.publicKey = publicKey;
    }

    // Interface methods
    @Override
    public BigInteger getY() {
        return publicKey;
    }

    @Override
    public DHParameterSpec getParams() {
        return new DHParameterSpec(modulus, generator);
    }

    @Override
    public String getAlgorithm() {
        return "DH";
    }

    @Override
    public String getFormat() {
        return "None";
    }

    @Override
    public byte[] getEncoded() {
        return publicKey.toByteArray();
    }
}
