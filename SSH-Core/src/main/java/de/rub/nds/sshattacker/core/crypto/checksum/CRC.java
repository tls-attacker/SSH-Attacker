/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.checksum;

public class CRC {

    private long reverseBits(long n, int numBits) {
        long result = 0;
        for (int i = 0; i < numBits; i++) {
            result = (result << 1) | ((n >> i) & 1);
        }
        return result;
    }

    private long mask;

    private int width;
    private long polynomial;
    private boolean reflectIn;
    private boolean reflectOut;
    private long init;
    private long finalXor;

    public long calculateCRC(byte[] data) {
        long curValue = this.init;
        long topBit = 1L << (this.width - 1);
        long mask = (topBit << 1) - 1;
        int end = data.length;

        for (int i = 0; i < end; i++) {
            long curByte = ((long) (data[i])) & 0x00FFL;
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

        curValue = curValue ^ this.finalXor;

        return curValue & mask;
    }

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
        if (this.width >= 64) {
            this.mask = 0;
        } else {
            this.mask = (1L << this.width) - 1;
        }
    }
}
