/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.constants;

public enum SftpVfsFlag {
    SSH_FXE_STATVFS_ST_RDONLY(0x0000000000000001),
    SSH_FXE_STATVFS_ST_NOSUID(0x0000000000000002);

    private final long value;

    SftpVfsFlag(long value) {
        this.value = value;
    }

    public long getValue() {
        return value;
    }

    public static boolean isFlagSet(long flags, SftpVfsFlag flag) {
        return (flags & flag.value) != 0;
    }

    public static long flagsToLong(SftpVfsFlag... vfsFlags) {
        long result = 0;
        for (SftpVfsFlag vfsFlag : vfsFlags) {
            result |= vfsFlag.value;
        }
        return result;
    }
}
