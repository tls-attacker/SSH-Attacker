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

public class CustomDhPublicKey implements DHPublicKey {

    private final BigInteger modulus;
    private final BigInteger generator;
    private final BigInteger publicKey;

    public CustomDhPublicKey(NamedDHGroup group, BigInteger publicKey) {
        this(group.getModulus(), group.getGenerator(), publicKey);
    }

    public CustomDhPublicKey(BigInteger modulus, BigInteger generator, BigInteger publicKey) {
        this.modulus = modulus;
        this.generator = generator;
        this.publicKey = publicKey;
    }

    @Override
    public BigInteger getY() {
        return publicKey;
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
