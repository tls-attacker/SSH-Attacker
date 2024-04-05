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
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.InvalidParameterSpecException;
import java.util.Objects;

/**
 * A serializable elliptic curve public key used in various EC-based algorithms like ECDH and ECDSA.
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class CustomEcPublicKey extends CustomPublicKey implements ECPublicKey {

    private Point publicKey;
    private NamedEcGroup group;

    public CustomEcPublicKey() {
        super();
    }

    public CustomEcPublicKey(Point publicKey, NamedEcGroup group) {
        super();
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

    @SuppressWarnings("SuspiciousGetterSetter")
    public Point getWAsPoint() {
        return publicKey;
    }

    @Override
    public ECPoint getW() {
        return new ECPoint(publicKey.getFieldX().getData(), publicKey.getFieldY().getData());
    }

    @SuppressWarnings("SuspiciousGetterSetter")
    public void setW(Point w) {
        publicKey = w;
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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CustomEcPublicKey that = (CustomEcPublicKey) o;
        return Objects.equals(publicKey, that.publicKey) && group == that.group;
    }

    @Override
    public int hashCode() {
        return Objects.hash(publicKey, group);
    }
}
