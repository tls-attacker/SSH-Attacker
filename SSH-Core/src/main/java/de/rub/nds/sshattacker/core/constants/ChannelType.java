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

public enum ChannelType {
    /*
     * Sources:
     * - https://www.iana.org/assignments/ssh-parameters/ssh-parameters.html#ssh-parameters-11
     * - https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL?annotate=HEAD
     */
    // [ RFC 4254 ]
    SESSION("session"),
    X11("x11"),
    FORWARDED_TCPIP("forwarded-tcpip"),
    DIRECT_TCPIP("direct-tcpip"),
    // Vendor extensions
    // [ OpenSSH ]
    TUN_OPENSSH_COM("tun@openssh.com"),
    DIRECT_STREAMLOCAL_OPENSSH_COM("direct-streamlocal@openssh.com"),
    FORWARDED_STREAMLOCAL_OPENSSH_COM("forwarded-streamlocal@openssh.com");

    private final String name;

    public static final Map<String, ChannelType> map;

    static {
        Map<String, ChannelType> mutableMap = new TreeMap<>();
        for (ChannelType channelType : values()) {
            mutableMap.put(channelType.name, channelType);
        }
        map = Collections.unmodifiableMap(mutableMap);
    }

    ChannelType(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return name;
    }

    public String getName() {
        return name;
    }

    public static ChannelType fromName(String name) {
        return map.get(name);
    }
}
