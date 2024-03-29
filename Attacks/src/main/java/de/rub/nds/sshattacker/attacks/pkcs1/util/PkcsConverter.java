/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.attacks.pkcs1.util;

import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public final class PkcsConverter {

    private static final Logger LOGGER = LogManager.getLogger();

    private PkcsConverter() {
        super();
    }

    public static byte[] doPkcs1Encoding(byte[] data, int modulusLenght) {
        int paddingLength = modulusLenght - 3 - data.length;
        LOGGER.info(paddingLength);
        byte[] padding = new byte[paddingLength];
        Arrays.fill(padding, (byte) 0xFF);
        byte[] encodedData = new byte[data.length + paddingLength + 2];
        encodedData[0] = 0x02;
        System.arraycopy(padding, 0, encodedData, 1, padding.length);
        encodedData[paddingLength + 3] = 0x00;
        System.arraycopy(data, 0, encodedData, paddingLength + 2, data.length);
        return encodedData;
    }

    public static byte[] doPkcsDecoding(byte[] encodedPayload) {
        encodedPayload = Arrays.copyOfRange(encodedPayload, 2, encodedPayload.length);

        int idx = 0;
        for (int i = 0; i < encodedPayload.length; i++) {
            if (encodedPayload[i] == 0x00) {
                idx = i;
                break;
            }
        }

        if (idx != 0) {
            idx = idx + 1;
        }

        return Arrays.copyOfRange(encodedPayload, idx, encodedPayload.length);
    }
}
