/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.mac;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.constants.MacAlgorithm;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

class JavaMac extends AbstractMac {

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
    public byte[] calculate(int sequenceNumber, byte[] unencryptedPacket) {
        byte[] macInput =
                ArrayConverter.concatenate(
                        ArrayConverter.intToBytes(sequenceNumber, DataFormatConstants.UINT32_SIZE),
                        unencryptedPacket);
        byte[] output = mac.doFinal(macInput);

        // Support for truncated MACs like hmac-sha1-96
        if (output.length > algorithm.getOutputSize()) {
            output = Arrays.copyOfRange(output, 0, algorithm.getOutputSize());
        }
        return output;
    }

    @Override
    public MacAlgorithm getAlgorithm() {
        return algorithm;
    }
}
