/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.constants;

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
    EOW_OPENSSH_COM("eow@openssh.com");

    private final String name;

    ChannelRequestType(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return name;
    }
}
