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

public enum ChannelRequestType {
    PTY_REQ("pty-req"),
    X11_REQ("x11_req"),
    ENV("env"),
    SHELL("shell"),
    EXEC("exec"),
    SUBSYSTEM("subsystem"),
    WINDOW_CHANGE("window-change"),
    XON_XOFF("xon-xoff"),
    SIGNAL("signal"),
    EXIT_STATUS("exit-status"),
    EXIT_SIGNAL("exit-signal");

    private final String name;

    ChannelRequestType(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return name;
    }
}
