/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.keys;

import de.rub.nds.sshattacker.core.constants.NamedDhGroup;
import java.math.BigInteger;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.spec.DHParameterSpec;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

/** A serializable diffie-hellman private key used in the DH key exchange. */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class CustomDhPrivateKey extends CustomPrivateKey implements DHPrivateKey {

    // Group parameters
    private BigInteger modulus;
    private BigInteger generator;

    // Private key
    private BigInteger privateKey;

    @SuppressWarnings("unused")
    private CustomDhPrivateKey() {}

    public CustomDhPrivateKey(NamedDhGroup group, BigInteger privateKey) {
        this(group.getModulus(), group.getGenerator(), privateKey);
    }

    public CustomDhPrivateKey(BigInteger modulus, BigInteger generator, BigInteger privateKey) {
        this.modulus = modulus;
        this.generator = generator;
        this.privateKey = privateKey;
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

    public BigInteger getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(BigInteger privateKey) {
        this.privateKey = privateKey;
    }

    // Interface methods
    @Override
    public BigInteger getX() {
        return privateKey;
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
        return privateKey.toByteArray();
    }
}
