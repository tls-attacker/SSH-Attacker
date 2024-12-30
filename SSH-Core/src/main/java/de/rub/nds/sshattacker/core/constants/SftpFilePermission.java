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
    // set user id on execution
    S_ISUID(04000),
    // set group id on execution
    S_ISGID(02000),
    // save swapped text even after use
    S_ISVTX(01000),
    // read permission, owner
    S_IRUSR(0400),
    // write permission, owner
    S_IWUSR(0200),
    // execute/search permission, owner
    S_IXUSR(0100),
    // read permission, group
    S_IRGRP(0040),
    // write permission, group
    S_IWGRP(0020),
    // execute/search permission, group
    S_IXGRP(0010),
    // read permission, other
    S_IROTH(0004),
    // write permission, other
    S_IWOTH(0002),
    // execute/search permission, other
    S_IXOTH(0001);

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
