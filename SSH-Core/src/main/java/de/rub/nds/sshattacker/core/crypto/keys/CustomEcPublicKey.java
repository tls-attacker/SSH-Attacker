/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.keys;

import de.rub.nds.sshattacker.core.constants.ECPointFormat;
import de.rub.nds.sshattacker.core.constants.NamedGroup;
import de.rub.nds.sshattacker.core.crypto.ec.Point;
import de.rub.nds.sshattacker.core.crypto.ec.PointFormatter;

import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.InvalidParameterSpecException;

public class CustomEcPublicKey implements ECPublicKey {

    public Point publicKey;

    public NamedGroup group;

    public CustomEcPublicKey(Point publicKey, NamedGroup group) {
        if (!group.isStandardCurve()) {
            throw new IllegalArgumentException("CustomEcPublicKey does not support named group " + group);
        }
        this.publicKey = publicKey;
        this.group = group;
    }

    public Point getWAsPoint() {
        return publicKey;
    }

    @Override
    public ECPoint getW() {
        return new ECPoint(publicKey.getFieldX().getData(), publicKey.getFieldY().getData());
    }

    @Override
    public String getAlgorithm() {
        return "EC";
    }

    @Override
    public String getFormat() {
        return "None";
    }

    @Override
    public byte[] getEncoded() {
        return PointFormatter.formatToByteArray(group, publicKey, ECPointFormat.UNCOMPRESSED);
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

    public static CustomEcPublicKey parse(byte[] encoded, NamedGroup group) {
        return new CustomEcPublicKey(PointFormatter.formatFromByteArray(group, encoded), group);
    }
}
