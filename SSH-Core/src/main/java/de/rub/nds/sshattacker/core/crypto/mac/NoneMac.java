/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.mac;

import de.rub.nds.sshattacker.core.constants.MacAlgorithm;

public class NoneMac implements WrappedMac {

    public NoneMac() {}

    @Override
    public byte[] calculate(byte[] data) {
        return new byte[0];
    }

    @Override
    public MacAlgorithm getAlgorithm() {
        return MacAlgorithm.NONE;
    }
}
