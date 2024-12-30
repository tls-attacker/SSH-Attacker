/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.constants;

public enum SftpFileAttributeFlag {
    /*
     * Sources:
     *  - https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#page-9
     *  - https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-03#page-9
     */
    SSH_FILEXFER_ATTR_SIZE(0x00000001),
    SSH_FILEXFER_ATTR_UIDGID(0x00000002), // No longer available since version 4
    // In version 4 it is unclear if the SSH_FILEXFER_ATTR_PERMISSIONS flag
    // should be used, but it is valid again in version 5
    SSH_FILEXFER_ATTR_PERMISSIONS(0x00000004),
    // Name of SSH_FILEXFER_ATTR_ACMODTIME changed to SSH_FILEXFER_ATTR_ACCESSTIME in version 4
    SSH_FILEXFER_ATTR_ACMODTIME(0x00000008),
    SSH_FILEXFER_ATTR_ACCESSTIME(0x00000008),
    SSH_FILEXFER_ATTR_EXTENDED(0x80000000),
    // [ From version 4 onwards ]
    SSH_FILEXFER_ATTR_CREATETIME(0x00000010),
    SSH_FILEXFER_ATTR_MODIFYTIME(0x00000020),
    SSH_FILEXFER_ATTR_ACL(0x00000040),
    SSH_FILEXFER_ATTR_OWNERGROUP(0x00000080),
    SSH_FILEXFER_ATTR_SUBSECOND_TIMES(0x00000100),
    // [ From version 5 onwards ]
    SSH_FILEXFER_ATTR_BITS(0x00000200);

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

    public static int flagsToInt(SftpFileAttributeFlag... attributeFlags) {
        int result = 0;
        for (SftpFileAttributeFlag attributeFlag : attributeFlags) {
            result |= attributeFlag.value; // Use bitwise OR to set each flag
        }
        return result;
    }
}
