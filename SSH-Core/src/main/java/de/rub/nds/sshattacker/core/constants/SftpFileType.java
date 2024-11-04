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

public enum SftpFileType {
    /*
     * Sources:
     *  - https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-03#section-5.2
     */
    // [ From version 4 onwards ]
    SSH_FILEXFER_TYPE_REGULAR((byte) 1),
    SSH_FILEXFER_TYPE_DIRECTORY((byte) 2),
    SSH_FILEXFER_TYPE_SYMLINK((byte) 3),
    SSH_FILEXFER_TYPE_SPECIAL((byte) 4),
    SSH_FILEXFER_TYPE_UNKNOWN((byte) 5);

    private final byte type;

    SftpFileType(byte type) {
        this.type = type;
    }

    public byte getType() {
        return type;
    }

    public static final Map<Byte, SftpFileType> map;

    static {
        Map<Byte, SftpFileType> mutableMap = new TreeMap<>();
        for (SftpFileType constant : values()) {
            mutableMap.put(constant.type, constant);
        }
        map = Collections.unmodifiableMap(mutableMap);
    }

    public static String getNameByType(byte type) {
        if (map.containsKey(type)) {
            return map.get(type).toString();
        } else {
            return String.format("%d", type);
        }
    }

    public static SftpFileType fromType(byte type) {
        return map.get(type);
    }
}
