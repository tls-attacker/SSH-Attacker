/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.checksum;

public class CRC {

    // Defines, how long the checksum should be
    private int width;
    // Defines which polynomnial should be used to calculate the checksum
    private long polynomial;
    // Defines, if the input-value should be reflected or not
    private boolean reflectIn;

    // Defines, if the output-value shut be reflected or not
    private boolean reflectOut;
    // Defines, which value should be used to init the alrogithm
    private long init;
    // Defines, if the last value should be xored or not
    private long finalXor;

    private long reverseBits(long n, int numBits) {
        long result = 0;
        for (int i = 0; i < numBits; i++) {
            result = (result << 1) | ((n >> i) & 1);
        }
        return result;
    }

    /**
     * Calculates the cyclic redundancy check (CRC) value for the given data.
     *
     * @param data the input data for which the CRC value is calculated
     * @return the calculated CRC value
     */
    public long calculateCRC(byte[] data) {
        long curValue = this.init;
        long topBit = 1L << (this.width - 1);
        long mask = (topBit << 1) - 1;

        for (byte b : data) {
            long curByte = ((long) (b)) & 0x00FFL;
            if (this.reflectIn) {
                curByte = reverseBits(curByte, 8);
            }

            for (int j = 0x80; j != 0; j >>= 1) {
                long bit = curValue & topBit;
                curValue <<= 1;

                if ((curByte & j) != 0) {
                    bit ^= topBit;
                }

                if (bit != 0) {
                    curValue ^= this.polynomial;
                }
            }
        }

        if (this.reflectOut) {
            curValue = reverseBits(curValue, this.width);
        }

        curValue ^= this.finalXor;

        return curValue & mask;
    }

    /**
     * This class represents a cyclic redundancy check (CRC). It calculates the CRC value for a
     * given input data. It can be used for any CRC-check calculation.
     */
    public CRC(
            int width,
            long polynomial,
            long init,
            boolean reflectIn,
            boolean reflectOut,
            long finalXor) {

        this.width = width;
        this.polynomial = polynomial;
        this.init = init;
        this.reflectIn = reflectIn;
        this.reflectOut = reflectOut;
        this.finalXor = finalXor;

        if (this.reflectIn) {
            this.init = reverseBits(this.init, width);
        }
    }

    /**
     * This class represents a cyclic redundancy check (CRC). It is used to calculate the CRC value
     * for a given input data. It sets the default values needed for sshv1
     */
    public CRC() {

        this.width = 32;
        this.polynomial = 0x0104C11DB7L;
        this.init = 0;
        this.reflectIn = true;
        this.reflectOut = true;
        this.finalXor = 0;

        if (this.reflectIn) {
            this.init = reverseBits(this.init, width);
        }
    }
}
