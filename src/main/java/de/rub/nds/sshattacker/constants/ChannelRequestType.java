package de.rub.nds.sshattacker.constants;

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

    private ChannelRequestType(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return name;
    }
}
