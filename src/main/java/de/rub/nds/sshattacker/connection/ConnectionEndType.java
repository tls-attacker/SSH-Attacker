package de.rub.nds.sshattacker.connection;

/**
 * Defines the connection end. Either client or server.
 */
public enum ConnectionEndType {

    CLIENT,
    SERVER;

    public ConnectionEndType getPeer() {
        if (this == CLIENT) {
            return SERVER;
        } else {
            return CLIENT;
        }
    }

}
