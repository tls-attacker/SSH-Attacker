/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.keys;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.NamedGroup;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * A serializable elliptic curve private key used in various EC-based algorithms like ECDH and
 * ECDSA.
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class CustomEcPrivateKey extends CustomPrivateKey implements ECPrivateKey {

    private NamedGroup group;
    private BigInteger privateKey;

    @SuppressWarnings("unused")
    private CustomEcPrivateKey() {}

    public CustomEcPrivateKey(BigInteger privateKey, NamedGroup group) {
        if (!group.isStandardCurve()) {
            throw new IllegalArgumentException(
                    "CustomEcPrivateKey does not support named group " + group);
        }
        this.group = group;
        this.privateKey = privateKey;
    }

    public NamedGroup getGroup() {
        return group;
    }

    public void setGroup(NamedGroup group) {
        this.group = group;
    }

    public BigInteger getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(BigInteger privateKey) {
        this.privateKey = privateKey;
    }

    public CustomEcPrivateKey parse(byte[] encoded, NamedGroup group) {
        return new CustomEcPrivateKey(new BigInteger(1, encoded), group);
    }

    // Interface methods
    @Override
    public BigInteger getS() {
        return privateKey;
    }

    @Override
    public ECParameterSpec getParams() {
        try {
            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec(group.getJavaName()));
            return parameters.getParameterSpec(ECParameterSpec.class);
        } catch (NoSuchAlgorithmException | InvalidParameterSpecException ex) {
            throw new UnsupportedOperationException("Could not generate ECParameterSpec", ex);
        }
    }

    @Override
    public String getAlgorithm() {
        return "EC";
    }

    @Override
    public String getFormat() {
        return "Octet";
    }

    @Override
    public byte[] getEncoded() {
        return ArrayConverter.bigIntegerToByteArray(privateKey);
    }
}
