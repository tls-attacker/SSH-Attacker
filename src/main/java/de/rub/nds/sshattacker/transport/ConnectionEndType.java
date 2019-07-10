package de.rub.nds.sshattacker.transport;

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
