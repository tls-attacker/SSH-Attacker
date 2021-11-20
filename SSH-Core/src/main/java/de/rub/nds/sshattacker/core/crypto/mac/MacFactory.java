/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.mac;

import de.rub.nds.sshattacker.core.constants.MacAlgorithm;
import de.rub.nds.sshattacker.core.packet.cipher.keys.KeySet;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import java.security.NoSuchAlgorithmException;

public class MacFactory {
    public static WrappedMac getWriteMac(
            MacAlgorithm algorithm, KeySet keySet, ConnectionEndType connectionEndType)
            throws NoSuchAlgorithmException {
        return getMac(algorithm, keySet.getWriteIntegrityKey(connectionEndType));
    }

    public static WrappedMac getReadMac(
            MacAlgorithm algorithm, KeySet keySet, ConnectionEndType connectionEndType)
            throws NoSuchAlgorithmException {
        return getMac(algorithm, keySet.getReadIntegrityKey(connectionEndType));
    }

    public static WrappedMac getMac(MacAlgorithm algorithm, byte[] key)
            throws NoSuchAlgorithmException {
        if (algorithm.getJavaName() != null) {
            return new JavaMac(algorithm, key);
        }
        throw new NoSuchAlgorithmException("MAC algorithm '" + algorithm + "' is not supported!");
    }

    private MacFactory() {}
}
