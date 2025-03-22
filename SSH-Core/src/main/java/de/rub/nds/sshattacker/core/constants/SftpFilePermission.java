/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.constants;

import java.util.*;

public enum SftpFilePermission {
    /*
     * Sources:
     *  - https://chromium.googlesource.com/native_client/nacl-newlib/+/a9ae3c60b36dea3d8a10e18b1b6db952d21268c2/newlib/libc/include/sys/stat.h#80
     */
    // is a directory
    IS_DIR(0040000),
    // is a character special file / character device
    IS_CHAR(0020000),
    // is block special
    IS_BLOCK(0060000),
    // is regular file
    IS_REGULAR(0100000),
    // is symbolic link
    IS_LINK(0120000),
    // is socket
    IS_SOCKET(0140000),
    // is fifo
    IS_FIFO(0010000),
    // set user id on execution
    SET_USER_ID(04000),
    // set group id on execution
    SET_GROUP_ID(02000),
    // save swapped text even after use or prevents users from deleting others' files in a directory
    STICKY_BIT(01000),
    // read permission, owner
    USER_READ(0400),
    // write permission, owner
    USER_WRITE(0200),
    // execute/search permission, owner
    USER_EXEC(0100),
    // read permission, group
    GROUP_READ(0040),
    // write permission, group
    GROUP_WRITE(0020),
    // execute/search permission, group
    GROUP_EXEC(0010),
    // read permission, other
    OTHER_READ(0004),
    // write permission, other
    OTHER_WRITE(0002),
    // execute/search permission, other
    OTHER_EXECUTE(0001);

    private final int value;

    SftpFilePermission(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    public static final Map<Integer, SftpFilePermission> map;

    static {
        Map<Integer, SftpFilePermission> mutableMap = new TreeMap<>();
        for (SftpFilePermission constant : values()) {
            mutableMap.put(constant.value, constant);
        }
        map = Collections.unmodifiableMap(mutableMap);
    }

    public static String getNameByValue(int value) {
        if (map.containsKey(value)) {
            return map.get(value).toString();
        } else {
            return String.format("%d", value);
        }
    }

    public static Set<SftpFilePermission> fromValue(int value) {
        Set<SftpFilePermission> permissions = EnumSet.noneOf(SftpFilePermission.class);
        for (SftpFilePermission permission : values()) {
            if ((value & permission.value) != 0) {
                permissions.add(permission);
            }
        }
        return permissions;
    }

    public static boolean isPermissionSet(SftpFilePermission permission, int value) {
        return (value & permission.value) != 0;
    }

    public static int permissionsToInt(SftpFilePermission... permissions) {
        int result = 0;
        for (SftpFilePermission permission : permissions) {
            result |= permission.value;
        }
        return result;
    }
}
