package de.rub.nds.sshattacker.constants;

public enum ChannelType {
    SESSION("session"),
    X11("x11"),
    FORWARDED_TCPIP("forwarded-tcpip"),
    DIRECT_TCPIP("direct-tcpip");

    private final String name;

    private ChannelType(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return name;
    }
}
