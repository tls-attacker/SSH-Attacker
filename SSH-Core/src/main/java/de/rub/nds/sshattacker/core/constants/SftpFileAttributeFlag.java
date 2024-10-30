/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.constants;

public enum SftpFileAttributeFlag {
    SSH_FILEXFER_ATTR_SIZE(0x00000001),
    SSH_FILEXFER_ATTR_UIDGID(0x00000002),
    SSH_FILEXFER_ATTR_PERMISSIONS(0x00000004),
    SSH_FILEXFER_ATTR_ACMODTIME(0x00000008),
    SSH_FILEXFER_ATTR_EXTENDED(0x80000000);

    private final int value;

    SftpFileAttributeFlag(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    public static boolean isFlagSet(int attributes, SftpFileAttributeFlag attribute) {
        return (attributes & attribute.value) != 0;
    }

    public static int getFlags(SftpFileAttributeFlag... attributes) {
        int result = 0;
        for (SftpFileAttributeFlag attribute : attributes) {
            result |= attribute.value; // Use bitwise OR to set each flag
        }
        return result;
    }
}
