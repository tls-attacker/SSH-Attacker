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

public enum CipherMethod {

    // Ciphermethods from ssh1.2.28
    SSH_CIPHER_NONE(0),
    SSH_CIPHER_IDEA(1),
    SSH_CIPHER_DES(2),
    SSH_CIPHER_3DES(3),
    CIPHER_NOT_SET(4),
    SSH_CIPHER_ARCFOUR(5),
    SSH_CIPHER_BLOWFISH(6),
    SSH_CIPHER_RESERVED(7);

    private final int id;

    public static final Map<Integer, CipherMethod> map;

    static {
        Map<Integer, CipherMethod> mutableMap = new TreeMap<>();
        for (CipherMethod constant : CipherMethod.values()) {
            mutableMap.put(constant.id, constant);
        }
        map = Collections.unmodifiableMap(mutableMap);
    }

    CipherMethod(int id) {
        this.id = id;
    }

    public int getId() {
        return id;
    }

    public static CipherMethod fromId(int id) {
        return map.get(id);
    }
}
