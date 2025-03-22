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

public enum SftpAceType {
    /*
     * Sources:
     *  - https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-03#section-5.7
     */
    // [ From version 4 onwards ]
    ACE4_ACCESS_ALLOWED_ACE_TYPE(0),
    ACE4_ACCESS_DENIED_ACE_TYPE(1),
    ACE4_SYSTEM_AUDIT_ACE_TYPE(2),
    ACE4_SYSTEM_ALARM_ACE_TYPE(3);

    private final int type;

    SftpAceType(int type) {
        this.type = type;
    }

    public int getType() {
        return type;
    }

    public static final Map<Integer, SftpAceType> map;

    static {
        Map<Integer, SftpAceType> mutableMap = new TreeMap<>();
        for (SftpAceType constant : values()) {
            mutableMap.put(constant.type, constant);
        }
        map = Collections.unmodifiableMap(mutableMap);
    }

    public static String getNameByType(int type) {
        if (map.containsKey(type)) {
            return map.get(type).toString();
        } else {
            return String.format("%d", type);
        }
    }

    public static SftpAceType fromType(int type) {
        return map.get(type);
    }
}
