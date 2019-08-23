package de.rub.nds.sshattacker.transport;

public enum SocketState {
    CLOSED,
    UP,
    DATA_AVAILABLE,
    TIMEOUT,
    SOCKET_EXCEPTION,
    IO_EXCEPTION
}
