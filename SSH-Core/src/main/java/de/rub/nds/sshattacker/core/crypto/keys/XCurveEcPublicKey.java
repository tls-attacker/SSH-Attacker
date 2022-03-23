/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.keys;

import de.rub.nds.modifiablevariable.util.UnformattedByteArrayAdapter;
import de.rub.nds.sshattacker.core.constants.CryptoConstants;
import de.rub.nds.sshattacker.core.constants.NamedGroup;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

/**
 * A serializable elliptic curve public key for X curves (Curve 25519 and Curve 448) used in the
 * X25519 / X448 key exchange.
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class XCurveEcPublicKey extends CustomPublicKey {

    private NamedGroup group;

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] coordinate;

    @SuppressWarnings("unused")
    public XCurveEcPublicKey() {}

    public XCurveEcPublicKey(byte[] coordinate, NamedGroup group) {
        if (!group.isRFC7748Curve()) {
            throw new IllegalArgumentException(
                    "XCurveEcPublicKey does not support named group " + group);
        }
        if ((group == NamedGroup.ECDH_X25519
                        && coordinate.length != CryptoConstants.X25519_POINT_SIZE)
                || group == NamedGroup.ECDH_X448
                        && coordinate.length != CryptoConstants.X448_POINT_SIZE) {
            throw new IllegalArgumentException(
                    "Tried to instantiate a new XCurveEcPublicKey with a mismatching coordinate length");
        }
        this.group = group;
        this.coordinate = coordinate;
    }

    public NamedGroup getGroup() {
        return group;
    }

    public void setGroup(NamedGroup group) {
        this.group = group;
    }

    public byte[] getCoordinate() {
        return coordinate;
    }

    public void setCoordinate(byte[] coordinate) {
        this.coordinate = coordinate;
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
        return coordinate;
    }
}
