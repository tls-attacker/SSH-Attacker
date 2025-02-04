/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.constants;

import java.util.Collections;
import java.util.Map;
import java.util.TreeMap;

public enum SftpPacketTypeConstant {
    /*
     * Sources:
     *  - https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02
     */
    // 1 - 2 protocol initialization
    SSH_FXP_INIT((byte) 1),
    SSH_FXP_VERSION((byte) 2),
    // 2 - 20 requests from the client to the server
    SSH_FXP_OPEN((byte) 3),
    SSH_FXP_CLOSE((byte) 4),
    SSH_FXP_READ((byte) 5),
    SSH_FXP_WRITE((byte) 6),
    SSH_FXP_LSTAT((byte) 7),
    SSH_FXP_FSTAT((byte) 8),
    SSH_FXP_SETSTAT((byte) 9),
    SSH_FXP_FSETSTAT((byte) 10),
    SSH_FXP_OPENDIR((byte) 11),
    SSH_FXP_READDIR((byte) 12),
    SSH_FXP_REMOVE((byte) 13),
    SSH_FXP_MKDIR((byte) 14),
    SSH_FXP_RMDIR((byte) 15),
    SSH_FXP_REALPATH((byte) 16),
    SSH_FXP_STAT((byte) 17),
    SSH_FXP_RENAME((byte) 18), // First added in version 2
    SSH_FXP_READLINK((byte) 19), // First added in version 3
    SSH_FXP_SYMLINK((byte) 20), // First added in version 3
    // 100 - 105 responses from the server to the client
    SSH_FXP_STATUS((byte) 101),
    SSH_FXP_HANDLE((byte) 102),
    SSH_FXP_DATA((byte) 103),
    SSH_FXP_NAME((byte) 104),
    SSH_FXP_ATTRS((byte) 105),
    // 200 - 201 vendor specific extensions
    SSH_FXP_EXTENDED((byte) 200), // First added in version 3
    SSH_FXP_EXTENDED_REPLY((byte) 201), // First added in version 3
    // [ Only version 6 ]
    SSH_FXP_LINK((byte) 21),
    SSH_FXP_BLOCK((byte) 22),
    SSH_FXP_UNBLOCK((byte) 23),
    // Unknown
    UNKNOWN((byte) 255);

    private final byte id;
    public static final Map<Byte, SftpPacketTypeConstant> map;

    static {
        Map<Byte, SftpPacketTypeConstant> mutableMap = new TreeMap<>();
        for (SftpPacketTypeConstant constant : values()) {
            mutableMap.put(constant.id, constant);
        }
        map = Collections.unmodifiableMap(mutableMap);
    }

    SftpPacketTypeConstant(byte id) {
        this.id = id;
    }

    public byte getId() {
        return id;
    }

    public static String getNameById(byte id) {
        if (map.containsKey(id)) {
            return map.get(id).toString();
        } else {
            return String.format("0x%02X", id);
        }
    }

    public static SftpPacketTypeConstant fromId(byte id) {
        if (map.containsKey(id)) {
            return map.get(id);
        }
        return UNKNOWN;
    }
}
