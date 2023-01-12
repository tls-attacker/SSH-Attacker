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

public enum ChannelRequestType {
    /*
     * Sources:
     * - https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml#ssh-parameters-13
     * - https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL?annotate=HEAD
     */
    // [ RFC 4254 ]
    PTY_REQ("pty-req"),
    X11_REQ("x11-req"),
    ENV("env"),
    SHELL("shell"),
    EXEC("exec"),
    SUBSYSTEM("subsystem"),
    WINDOW_CHANGE("window-change"),
    XON_XOFF("xon-xoff"),
    SIGNAL("signal"),
    EXIT_STATUS("exit-status"),
    EXIT_SIGNAL("exit-signal"),
    // [ RFC 4335 ]
    BREAK("break"),
    // Vendor extensions
    // [ OpenSSH ]
    AUTH_AGENT_REQ_OPENSSH_COM("auth-agent-req@openssh.com"),
    EOW_OPENSSH_COM("eow@openssh.com");

    private final String name;

    public static final Map<String, ChannelRequestType> map;

    static {
        Map<String, ChannelRequestType> mutableMap = new TreeMap<>();
        for (ChannelRequestType requestType : ChannelRequestType.values()) {
            mutableMap.put(requestType.name, requestType);
        }
        map = Collections.unmodifiableMap(mutableMap);
    }

    ChannelRequestType(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return name;
    }

    public String getName() {
        return name;
    }

    public static ChannelRequestType fromName(String name) {
        return map.get(name);
    }
}
