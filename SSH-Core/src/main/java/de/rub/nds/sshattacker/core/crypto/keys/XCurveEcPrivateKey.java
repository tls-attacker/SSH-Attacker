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

import de.rub.nds.sshattacker.core.constants.CryptoConstants;
import de.rub.nds.sshattacker.core.constants.NamedGroup;

import java.security.PrivateKey;

public class XCurveEcPrivateKey implements PrivateKey {

    private final NamedGroup group;
    private final byte[] scalar;

    public XCurveEcPrivateKey(byte[] scalar, NamedGroup group) {
        if (!group.isRFC7748Curve()) {
            throw new IllegalArgumentException("XCurveEcPrivateKey does not support named group " + group);
        }
        if ((group == NamedGroup.ECDH_X25519 && scalar.length != CryptoConstants.X25519_POINT_SIZE)
                || group == NamedGroup.ECDH_X448 && scalar.length != CryptoConstants.X448_POINT_SIZE) {
            throw new IllegalArgumentException(
                    "Tried to instantiate a new XCurveEcPrivateKey with a mismatching scalar length");
        }
        this.group = group;
        this.scalar = scalar;
    }

    public NamedGroup getGroup() {
        return group;
    }

    public byte[] getScalar() {
        return scalar;
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
        return scalar;
    }
}
