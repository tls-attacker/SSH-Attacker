/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.keys;

import de.rub.nds.sshattacker.core.constants.CryptoConstants;
import de.rub.nds.sshattacker.core.constants.NamedGroup;
import java.security.PublicKey;

public class XCurveEcPublicKey implements PublicKey {

    private final NamedGroup group;
    private final byte[] coordinate;

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

    public byte[] getCoordinate() {
        return coordinate;
    }

    public NamedGroup getGroup() {
        return group;
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
        return coordinate;
    }
}
