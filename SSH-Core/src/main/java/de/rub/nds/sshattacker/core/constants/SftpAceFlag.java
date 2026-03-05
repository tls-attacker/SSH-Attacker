/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.constants;

public enum SftpAceFlag {
    /*
     * Sources:
     *  - https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-03#section-5.7
     */
    // [ From version 4 onwards ]
    ACE4_FILE_INHERIT_ACE(0x00000001),
    ACE4_DIRECTORY_INHERIT_ACE(0x00000002),
    ACE4_NO_PROPAGATE_INHERIT_ACE(0x00000004),
    ACE4_INHERIT_ONLY_ACE(0x00000008),
    ACE4_SUCCESSFUL_ACCESS_ACE_FLAG(0x00000010),
    ACE4_FAILED_ACCESS_ACE_FLAG(0x00000020),
    ACE4_IDENTIFIER_GROUP(0x00000040);

    private final int value;

    SftpAceFlag(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    public static boolean isFlagSet(int flags, SftpAceFlag aceFlag) {
        return (flags & aceFlag.value) != 0;
    }

    public static int flagsToInt(SftpAceFlag... aceFlags) {
        int result = 0;
        for (SftpAceFlag aceFlag : aceFlags) {
            result |= aceFlag.value;
        }
        return result;
    }
}
