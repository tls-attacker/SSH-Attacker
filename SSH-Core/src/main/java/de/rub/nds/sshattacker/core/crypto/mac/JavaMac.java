/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.mac;

import de.rub.nds.sshattacker.core.constants.MacAlgorithm;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class JavaMac implements WrappedMac {

    private final MacAlgorithm algorithm;

    private final Mac mac;

    public JavaMac(MacAlgorithm algorithm, byte[] key) {
        this.algorithm = algorithm;
        try {
            mac = Mac.getInstance(algorithm.getJavaName());
            mac.init(new SecretKeySpec(key, mac.getAlgorithm()));
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new UnsupportedOperationException("MAC algorithm not supported: " + algorithm, e);
        }
    }

    @Override
    public byte[] calculate(byte[] data) {
        return mac.doFinal(data);
    }

    @Override
    public MacAlgorithm getAlgorithm() {
        return algorithm;
    }
}
