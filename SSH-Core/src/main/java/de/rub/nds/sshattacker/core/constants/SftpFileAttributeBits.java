/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.constants;

public enum SftpFileAttributeBits {
    /*
     * Sources:
     *  - https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-05#page-17
     */
    // [ From version 5 onwards ]
    SSH_FILEXFER_ATTR_FLAGS_READONLY(0x00000001),
    SSH_FILEXFER_ATTR_FLAGS_SYSTEM(0x00000002),
    SSH_FILEXFER_ATTR_FLAGS_HIDDEN(0x00000004),
    SSH_FILEXFER_ATTR_FLAGS_CASE_INSENSITIVE(0x00000008),
    SSH_FILEXFER_ATTR_FLAGS_ARCHIVE(0x00000010),
    SSH_FILEXFER_ATTR_FLAGS_ENCRYPTED(0x00000020),
    SSH_FILEXFER_ATTR_FLAGS_COMPRESSED(0x00000040),
    SSH_FILEXFER_ATTR_FLAGS_SPARSE(0x00000080),
    SSH_FILEXFER_ATTR_FLAGS_APPEND_ONLY(0x00000100),
    SSH_FILEXFER_ATTR_FLAGS_IMMUTABLE(0x00000200),
    SSH_FILEXFER_ATTR_FLAGS_SYNC(0x00000400);

    private final int value;

    SftpFileAttributeBits(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    public static boolean isBitSet(int bits, SftpFileAttributeBits bit) {
        return (bits & bit.value) != 0;
    }

    public static int bitsToInt(SftpFileAttributeBits... attributeBits) {
        int result = 0;
        for (SftpFileAttributeBits attributeBit : attributeBits) {
            result |= attributeBit.value;
        }
        return result;
    }
}
