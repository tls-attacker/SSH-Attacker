/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.constants;

public enum SftpAceMask {
    /*
     * Sources:
     *  - https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-03#section-5.7
     */
    // [ From version 4 onwards ]
    ACE4_READ_DATA(0x00000001),
    ACE4_LIST_DIRECTORY(0x00000001),
    ACE4_WRITE_DATA(0x00000002),
    ACE4_ADD_FILE(0x00000002),
    ACE4_APPEND_DATA(0x00000004),
    ACE4_ADD_SUBDIRECTORY(0x00000004),
    ACE4_READ_NAMED_ATTRS(0x00000008),
    ACE4_WRITE_NAMED_ATTRS(0x00000010),
    ACE4_EXECUTE(0x00000020),
    ACE4_DELETE_CHILD(0x00000040),
    ACE4_READ_ATTRIBUTES(0x00000080),
    ACE4_WRITE_ATTRIBUTES(0x00000100),
    ACE4_DELETE(0x00010000),
    ACE4_READ_ACL(0x00020000),
    ACE4_WRITE_ACL(0x00040000),
    ACE4_WRITE_OWNER(0x00080000),
    ACE4_SYNCHRONIZE(0x00100000);

    private final int value;

    SftpAceMask(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    public static boolean isFlagSet(int flags, SftpAceMask flag) {
        return (flags & flag.value) != 0;
    }

    public static int flagsToInt(SftpAceMask... flags) {
        int result = 0;
        for (SftpAceMask flag : flags) {
            result |= flag.value;
        }
        return result;
    }
}
