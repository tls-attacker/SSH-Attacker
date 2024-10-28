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
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import java.util.Objects;

/**
 * A serializable elliptic curve public key used in various EC-based algorithms like ECDH and ECDSA.
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class CustomEcPublicKey extends CustomPublicKey implements ECPublicKey {

    protected Point publicKey; // Public key as Point
    protected NamedEcGroup group;

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

    public CustomEcPublicKey(BigInteger x, BigInteger y, NamedEcGroup group) {
        super();
        this.group = group;
        publicKey = Point.createPoint(x, y, group);
    }

    public CustomEcPublicKey(ECPublicKey publicKey) throws CryptoException {
        super();
        group =
                Arrays.stream(NamedEcGroup.values())
                        .filter(
                                v ->
                                        Objects.equals(
                                                v.getJavaName(),
                                                publicKey.getParams().getCurve().toString()))
                        .findFirst()
                        .orElseThrow(CryptoException::new);
        this.publicKey =
                Point.createPoint(
                        publicKey.getW().getAffineX(), publicKey.getW().getAffineY(), group);
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
}
