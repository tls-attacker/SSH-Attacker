/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.constants;

import java.util.Map;
import java.util.TreeMap;

public enum SftpExtension {
    /*
     * Sources:
     *  - https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-extensions-00
     *      - 2. vendor-id
     *      - 3. check-file
     *      - 4. space-available
     *      - 5. home-directory
     *      - 6. copy-file
     *      - 7. copy-data
     *  - http://cvsweb.openbsd.org/cgi-bin/cvsweb/~checkout~/src/usr.bin/ssh/PROTOCOL
     *      - 4.3. posix-rename@openssh.com
     *      - 4.4. statvfs@openssh.com
     *      - 4.5. hardlink@openssh.com
     *      - 4.6. fsync@openssh.com
     *      - 4.7. lsetstat@openssh.com
     *      - 4.8. limits@openssh.com
     *      - 4.9. expand-path@openssh.com
     *      - 4.10. expand-path@openssh.com
     *      - 4.12. users-groups-by-id@openssh.com
     * - SFTP v4: https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-03
     *      - 4.3. new-line
     *      - 6.3. text-seek
     */
    // SFTP
    VENDOR_ID("vendor-id"),
    CHECK_FILE("check-file"),
    CHECK_FILE_HANDLE(
            "check-file-handle"), // only as request name - available if check-file was announced
    CHECK_FILE_NAME(
            "check-file-name"), // only as request name - available if check-file was announced
    SPACE_AVAILABLE("space-available"),
    HOME_DIRECTORY("home-directory"),
    COPY_FILE("copy-file"),
    COPY_DATA("copy-data"),
    GET_TEMP_FOLDER("get-temp-folder"),
    MAKE_TEMP_FOLDER("make-temp-folder"),
    // SFTP v4
    TEXT_SEEK("text-seek"),
    NEWLINE("newline"),
    // Vendor extensions
    POSIX_RENAME_OPENSSH_COM("posix-rename@openssh.com"),
    STAT_VFS_OPENSSH_COM("statvfs@openssh.com"),
    F_STAT_VFS_OPENSSH_COM("fstatvfs@openssh.com"),
    HARDLINK_OPENSSH_COM("hardlink@openssh.com"),
    F_SYNC_OPENSSH_COM("fsync@openssh.com"),
    L_SET_STAT("lsetstat@openssh.com"),
    LIMITS("limits@openssh.com"),
    EXPAND_PATH("expand-path@openssh.com"),
    USERS_GROUPS_BY_ID("users-groups-by-id@openssh.com"),

    UNKNOWN(null);

    private final String name;

    private static final Map<String, SftpExtension> map;

    static {
        map = new TreeMap<>();
        for (SftpExtension extension : values()) {
            if (extension.name != null) {
                map.put(extension.name, extension);
            }
        }
    }

    SftpExtension(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return name;
    }

    public String getName() {
        return name;
    }

    public static SftpExtension fromName(String name) {
        SftpExtension result = map.get(name);
        if (result != null) {
            return result;
        }
        return UNKNOWN;
    }
}
