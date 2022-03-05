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
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.spec.DHParameterSpec;

public class CustomDhPrivateKey implements DHPrivateKey {

    private final BigInteger privateKey;
    private final BigInteger modulus;
    private final BigInteger generator;

    public CustomDhPrivateKey(NamedDHGroup group, BigInteger privateKey) {
        this(group.getModulus(), group.getGenerator(), privateKey);
    }

    public CustomDhPrivateKey(BigInteger modulus, BigInteger generator, BigInteger privateKey) {
        this.modulus = modulus;
        this.generator = generator;
        this.privateKey = privateKey;
    }

    @Override
    public BigInteger getX() {
        return privateKey;
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

    @Override
    public DHParameterSpec getParams() {
        return new DHParameterSpec(modulus, generator);
    }

    public BigInteger getModulus() {
        return modulus;
    }

    public BigInteger getGenerator() {
        return generator;
    }
}
