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

public enum AuthenticationMethodSSHv1 {

    // Ciphermethods from ssh1.2.28
    SSH_CIPHER_NONE(0),
    SSH_AUTH_RHOSTS(1),
    SSH_AUTH_RSA(2),
    SSH_AUTH_PASSWORD(3),
    SSH_AUTH_RHOSTS_RSA(4),
    SSH_AUTH_TIS(5),
    SSSSH_AUTH_KERBEROSH_CIPHER_RESERVED(6),
    SSH_PASS_KERBEROS_TGT(7);

    private final int id;

    public static final Map<Integer, AuthenticationMethodSSHv1> map;

    static {
        Map<Integer, AuthenticationMethodSSHv1> mutableMap = new TreeMap<>();
        for (AuthenticationMethodSSHv1 constant : AuthenticationMethodSSHv1.values()) {
            mutableMap.put(constant.id, constant);
        }
        map = Collections.unmodifiableMap(mutableMap);
    }

    AuthenticationMethodSSHv1(int id) {
        this.id = id;
    }

    public int getId() {
        return id;
    }

    public static AuthenticationMethodSSHv1 fromId(int id) {
        return map.get(id);
    }
}
