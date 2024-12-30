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

public enum SftpAceSpecialIdentifiers {
    /*
     * Sources:
     *  - https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-04#section-5.7
     */
    // [ From version 4 onwards ]
    OWNER("OWNER@"),
    GROUP("GROUP@"),
    EVERYONE("EVERYONE@"),
    INTERACTIVE("INTERACTIVE@"),
    NETWORK("NETWORK@"),
    DIALUP("DIALUP@"),
    BATCH("BATCH@"),
    ANONYMOUS("ANONYMOUS@"),
    AUTHENTICATED("AUTHENTICATED@"),
    SERVICE("SERVICE@");

    private final String who;

    SftpAceSpecialIdentifiers(String who) {
        this.who = who;
    }

    public String getWho() {
        return who;
    }

    public static final Map<String, SftpAceSpecialIdentifiers> map;

    static {
        Map<String, SftpAceSpecialIdentifiers> mutableMap = new TreeMap<>();
        for (SftpAceSpecialIdentifiers constant : values()) {
            mutableMap.put(constant.who, constant);
        }
        map = Collections.unmodifiableMap(mutableMap);
    }

    public static SftpAceSpecialIdentifiers fromWho(String who) {
        return map.get(who);
    }
}
