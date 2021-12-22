/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.constants;

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

    ChannelType(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return name;
    }

    public static ChannelType getByString(String name) {
        for (ChannelType channelType : ChannelType.values()) {
            if (channelType.name.equals(name)) {
                return channelType;
            }
        }
        return null;
    }
}
