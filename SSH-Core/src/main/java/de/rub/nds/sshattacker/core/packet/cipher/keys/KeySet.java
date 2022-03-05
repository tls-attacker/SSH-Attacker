/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.packet.cipher.keys;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;

public class KeySet {

    private byte[] clientWriteInitialIV;
    private byte[] serverWriteInitialIV;
    private byte[] clientWriteEncryptionKey;
    private byte[] serverWriteEncryptionKey;
    private byte[] clientWriteIntegrityKey;
    private byte[] serverWriteIntegrityKey;

    public KeySet() {}

    public byte[] getClientWriteInitialIV() {
        return clientWriteInitialIV;
    }

    public void setClientWriteInitialIV(byte[] clientWriteInitialIV) {
        this.clientWriteInitialIV = clientWriteInitialIV;
    }

    public byte[] getServerWriteInitialIV() {
        return serverWriteInitialIV;
    }

    public void setServerWriteInitialIV(byte[] serverWriteInitialIV) {
        this.serverWriteInitialIV = serverWriteInitialIV;
    }

    public byte[] getClientWriteEncryptionKey() {
        return clientWriteEncryptionKey;
    }

    public void setClientWriteEncryptionKey(byte[] clientWriteEncryptionKey) {
        this.clientWriteEncryptionKey = clientWriteEncryptionKey;
    }

    public byte[] getServerWriteEncryptionKey() {
        return serverWriteEncryptionKey;
    }

    public void setServerWriteEncryptionKey(byte[] serverWriteEncryptionKey) {
        this.serverWriteEncryptionKey = serverWriteEncryptionKey;
    }

    public byte[] getClientWriteIntegrityKey() {
        return clientWriteIntegrityKey;
    }

    public void setClientWriteIntegrityKey(byte[] clientWriteIntegrityKey) {
        this.clientWriteIntegrityKey = clientWriteIntegrityKey;
    }

    public byte[] getServerWriteIntegrityKey() {
        return serverWriteIntegrityKey;
    }

    public void setServerWriteIntegrityKey(byte[] serverWriteIntegrityKey) {
        this.serverWriteIntegrityKey = serverWriteIntegrityKey;
    }

    public byte[] getWriteIv(ConnectionEndType connectionEndType) {
        if (connectionEndType == ConnectionEndType.CLIENT) {
            return clientWriteInitialIV;
        } else {
            return serverWriteInitialIV;
        }
    }

    public byte[] getReadIv(ConnectionEndType connectionEndType) {
        if (connectionEndType == ConnectionEndType.CLIENT) {
            return serverWriteInitialIV;
        } else {
            return clientWriteInitialIV;
        }
    }

    public byte[] getWriteEncryptionKey(ConnectionEndType connectionEndType) {
        if (connectionEndType == ConnectionEndType.CLIENT) {
            return clientWriteEncryptionKey;
        } else {
            return serverWriteEncryptionKey;
        }
    }

    public byte[] getReadEncryptionKey(ConnectionEndType connectionEndType) {
        if (connectionEndType == ConnectionEndType.CLIENT) {
            return serverWriteEncryptionKey;
        } else {
            return clientWriteEncryptionKey;
        }
    }

    public byte[] getWriteIntegrityKey(ConnectionEndType connectionEndType) {
        if (connectionEndType == ConnectionEndType.CLIENT) {
            return clientWriteIntegrityKey;
        } else {
            return serverWriteIntegrityKey;
        }
    }

    public byte[] getReadIntegrityKey(ConnectionEndType connectionEndType) {
        if (connectionEndType == ConnectionEndType.CLIENT) {
            return serverWriteIntegrityKey;
        } else {
            return clientWriteIntegrityKey;
        }
    }

    @Override
    public String toString() {
        return "Initial IV (client to server): "
                + ArrayConverter.bytesToRawHexString(clientWriteInitialIV)
                + "\n"
                + "Initial IV (server to client): "
                + ArrayConverter.bytesToRawHexString(serverWriteInitialIV)
                + "\n"
                + "Encryption key (client to server): "
                + ArrayConverter.bytesToRawHexString(clientWriteEncryptionKey)
                + "\n"
                + "Encryption key (server to client): "
                + ArrayConverter.bytesToRawHexString(serverWriteEncryptionKey)
                + "\n"
                + "Integrity key (client to server): "
                + ArrayConverter.bytesToRawHexString(clientWriteIntegrityKey)
                + "\n"
                + "Integrity key (server to client): "
                + ArrayConverter.bytesToRawHexString(serverWriteIntegrityKey);
    }
}
