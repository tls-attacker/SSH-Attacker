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

public enum SftpStatusCode {
    /*
     * Sources:
     *  - https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02#page-21
     */
    // [ From version 3 onwards ]
    SSH_FX_OK(0),
    SSH_FX_EOF(1),
    SSH_FX_NO_SUCH_FILE(2),
    SSH_FX_PERMISSION_DENIED(3),
    SSH_FX_FAILURE(4),
    SSH_FX_BAD_MESSAGE(5),
    SSH_FX_NO_CONNECTION(6),
    SSH_FX_CONNECTION_LOST(7),
    SSH_FX_OP_UNSUPPORTED(8),
    // [ From version 4 onwards ]
    SSH_FX_INVALID_HANDLE(9),
    SSH_FX_NO_SUCH_PATH(10),
    SSH_FX_FILE_ALREADY_EXISTS(11),
    SSH_FX_WRITE_PROTECT(12);

    private final int code;

    SftpStatusCode(int code) {
        this.code = code;
    }

    public int getCode() {
        return code;
    }

    public static final Map<Integer, SftpStatusCode> map;

    static {
        Map<Integer, SftpStatusCode> mutableMap = new TreeMap<>();
        for (SftpStatusCode constant : values()) {
            mutableMap.put(constant.code, constant);
        }
        map = Collections.unmodifiableMap(mutableMap);
    }

    public static String getNameByCode(int code) {
        if (map.containsKey(code)) {
            return map.get(code).toString();
        } else {
            return String.format("%d", code);
        }
    }

    public static SftpStatusCode fromCode(int code) {
        return map.get(code);
    }
}
