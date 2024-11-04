/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.constants;

public enum SftpFileOpenFlag {
    /*
     * Sources:
     *  - https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#page-12
     *  - https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-03#page-15
     */
    // [ From version 3 onwards ]
    SSH_FXF_READ(0x00000001),
    SSH_FXF_WRITE(0x00000002),
    SSH_FXF_APPEND(0x00000004),
    SSH_FXF_CREAT(0x00000008),
    SSH_FXF_TRUNC(0x00000010),
    SSH_FXF_EXCL(0x00000020),
    // [ From version 4 onwards ]
    SSH_FXF_TEXT(0x00000040);

    private final int value;

    SftpFileOpenFlag(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    public static boolean isFlagSet(int attributes, SftpFileOpenFlag attribute) {
        return (attributes & attribute.value) != 0;
    }

    public static int flagsToInt(SftpFileOpenFlag... fileOpenFlags) {
        int result = 0;
        for (SftpFileOpenFlag fileOpenFlag : fileOpenFlags) {
            result |= fileOpenFlag.value; // Use bitwise OR to set each flag
        }
        return result;
    }
}
