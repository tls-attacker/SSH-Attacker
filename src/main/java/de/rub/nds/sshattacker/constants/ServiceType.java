package de.rub.nds.sshattacker.constants;

public enum ServiceType {
    SSH_USERAUTH("ssh-userauth"),
    SSH_CONNECTION("ssh-connection");

    private final String name;

    private ServiceType(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return name;
    }
}
