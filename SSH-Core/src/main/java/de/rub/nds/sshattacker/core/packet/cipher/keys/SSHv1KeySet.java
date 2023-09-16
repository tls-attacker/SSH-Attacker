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
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.Arrays;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class SSHv1KeySet extends AbstractKeySet {

    private byte[] clientWriteInitialIv;
    private byte[] serverWriteInitialIv;
    private byte[] clientWriteEncryptionKey;
    private byte[] serverWriteEncryptionKey;

    public SSHv1KeySet() {}

    public byte[] getClientWriteInitialIv() {
        return clientWriteInitialIv;
    }

    public void setClientWriteInitialIv(byte[] clientWriteInitialIv) {
        this.clientWriteInitialIv = clientWriteInitialIv;
    }

    public byte[] getServerWriteInitialIv() {
        return serverWriteInitialIv;
    }

    public void setServerWriteInitialIv(byte[] serverWriteInitialIv) {
        this.serverWriteInitialIv = serverWriteInitialIv;
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

    public byte[] getWriteIv(ConnectionEndType connectionEndType) {
        if (connectionEndType == ConnectionEndType.CLIENT) {
            return clientWriteInitialIv;
        } else {
            return serverWriteInitialIv;
        }
    }

    public byte[] getReadIv(ConnectionEndType connectionEndType) {
        if (connectionEndType == ConnectionEndType.CLIENT) {
            return serverWriteInitialIv;
        } else {
            return clientWriteInitialIv;
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

    @Override
    public String toString() {
        return "Initial IV (client to server): "
                + ArrayConverter.bytesToRawHexString(clientWriteInitialIv)
                + "\n"
                + "Initial IV (server to client): "
                + ArrayConverter.bytesToRawHexString(serverWriteInitialIv)
                + "\n"
                + "Encryption key (client to server): "
                + ArrayConverter.bytesToRawHexString(clientWriteEncryptionKey)
                + "\n"
                + "Encryption key (server to client): "
                + ArrayConverter.bytesToRawHexString(serverWriteEncryptionKey);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SSHv1KeySet keySet = (SSHv1KeySet) o;
        return Arrays.equals(clientWriteInitialIv, keySet.clientWriteInitialIv)
                && Arrays.equals(serverWriteInitialIv, keySet.serverWriteInitialIv)
                && Arrays.equals(clientWriteEncryptionKey, keySet.clientWriteEncryptionKey)
                && Arrays.equals(serverWriteEncryptionKey, keySet.serverWriteEncryptionKey);
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(clientWriteInitialIv);
        result = 31 * result + Arrays.hashCode(serverWriteInitialIv);
        result = 31 * result + Arrays.hashCode(clientWriteEncryptionKey);
        result = 31 * result + Arrays.hashCode(serverWriteEncryptionKey);
        return result;
    }
}
