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

public class PkcsConverter {

    private static final Logger LOGGER = LogManager.getLogger();

    public PkcsConverter() {}

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

    public static byte[] doPkcs1EncodingWithWrongHeader(byte[] data, int modulusLenght) {
        int paddingLength = modulusLenght - 3 - data.length;
        byte[] padding = new byte[paddingLength];
        Arrays.fill(padding, (byte) 0xFF);
        byte[] encodedData = new byte[data.length + paddingLength + 3];
        encodedData[0] = 0x00;
        encodedData[1] = 0x49;
        System.arraycopy(padding, 0, encodedData, 2, padding.length);
        encodedData[paddingLength + 3] = 0x00;
        System.arraycopy(data, 0, encodedData, paddingLength + 3, data.length);
        return encodedData;
    }

    public static byte[] doPkcs1EncodingWithWrongZeroByte(
            byte[] data, int modulusLenght, int position) {

        byte[] noZeroByte = doPkcs1EncodingWithOutZeroByte(data, modulusLenght);
        noZeroByte[position] = 0x00;

        return noZeroByte;
    }

    public static byte[] doPkcs1EncodingWithOutZeroByte(byte[] data, int modulusLenght) {
        int paddingLength = modulusLenght - 2 - data.length;
        byte[] padding = new byte[paddingLength];
        Arrays.fill(padding, (byte) 0xFF);
        byte[] encodedData = new byte[data.length + paddingLength + 2];
        encodedData[0] = 0x00;
        encodedData[1] = 0x02;
        System.arraycopy(padding, 0, encodedData, 2, padding.length);
        System.arraycopy(data, 0, encodedData, paddingLength + 2, data.length);
        return encodedData;
    }

    public static byte[] doPkcsDecoding(byte[] data) {
        // do PKCS1.5 Decoding of data
        int index = 0;
        for (int i = 0; i < data.length; i++) {
            if (data[i] == 0x00) {
                index = i;
                break;
            }
        }
        byte[] decodedData = new byte[data.length - index - 1];
        System.arraycopy(data, index + 1, decodedData, 0, decodedData.length);
        return decodedData;
    }
}
