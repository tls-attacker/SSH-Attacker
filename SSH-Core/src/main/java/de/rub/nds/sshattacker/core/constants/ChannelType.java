/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.constants;

public enum ChannelType {
    SESSION("session"),
    X11("x11"),
    FORWARDED_TCPIP("forwarded-tcpip"),
    DIRECT_TCPIP("direct-tcpip");

    private final String name;

    ChannelType(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return name;
    }
}
