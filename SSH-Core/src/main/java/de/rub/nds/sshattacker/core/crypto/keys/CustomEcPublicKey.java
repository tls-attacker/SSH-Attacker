/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.keys;

import de.rub.nds.sshattacker.core.constants.EcPointFormat;
import de.rub.nds.sshattacker.core.constants.NamedEcGroup;
import de.rub.nds.sshattacker.core.crypto.ec.Point;
import de.rub.nds.sshattacker.core.crypto.ec.PointFormatter;
import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.InvalidParameterSpecException;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * A serializable elliptic curve public key used in various EC-based algorithms like ECDH and ECDSA.
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class CustomEcPublicKey extends CustomPublicKey implements ECPublicKey {

    private Point publicKey;
    private NamedEcGroup group;

    @SuppressWarnings("unused")
    public CustomEcPublicKey() {}

    public CustomEcPublicKey(Point publicKey, NamedEcGroup group) {
        if (group.isRFC7748Curve()) {
            throw new IllegalArgumentException(
                    "CustomEcPublicKey does not support named group " + group);
        }
        this.publicKey = publicKey;
        this.group = group;
    }

    public NamedEcGroup getGroup() {
        return group;
    }

    public void setGroup(NamedEcGroup group) {
        this.group = group;
    }

    public Point getWAsPoint() {
        return publicKey;
    }

    @Override
    public ECPoint getW() {
        return new ECPoint(publicKey.getFieldX().getData(), publicKey.getFieldY().getData());
    }

    public void setW(Point w) {
        this.publicKey = w;
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
        return PointFormatter.formatToByteArray(group, publicKey, EcPointFormat.UNCOMPRESSED);
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

    public static CustomEcPublicKey parse(byte[] encoded, NamedEcGroup group) {
        return new CustomEcPublicKey(PointFormatter.formatFromByteArray(group, encoded), group);
    }
}
