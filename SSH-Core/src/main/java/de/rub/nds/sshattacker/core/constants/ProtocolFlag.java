/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.constants;

import java.util.Collections;
import java.util.Map;
import java.util.TreeMap;

public enum ProtocolFlag {

    // Ciphermethods from ssh1.2.28
    SSH_PROTOFLAG_SCREEN_NUMBER(1),
    SSH_PROTOFLAG_HOST_IN_FWD_OPEN(2);

    private final int id;

    public static final Map<Integer, ProtocolFlag> map;

    static {
        Map<Integer, ProtocolFlag> mutableMap = new TreeMap<>();
        for (ProtocolFlag constant : ProtocolFlag.values()) {
            mutableMap.put(constant.id, constant);
        }
        map = Collections.unmodifiableMap(mutableMap);
    }

    ProtocolFlag(int id) {
        this.id = id;
    }

    public int getId() {
        return id;
    }

    public static ProtocolFlag fromId(int id) {
        return map.get(id);
    }
}
