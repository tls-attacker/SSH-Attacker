/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.session.cipher;

import de.rub.nds.sshattacker.core.constants.CompressionAlgorithm;
import de.rub.nds.sshattacker.core.constants.EncryptionAlgorithm;
import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.sshattacker.core.constants.MacAlgorithm;
import de.rub.nds.sshattacker.core.session.cipher.cryptohelper.KeySet;

public class CipherState {

    /*private ProtocolVersion protocolVersion;
    private CipherSuite cipherSuite;*/
    private CompressionAlgorithm compressionAlgorithm;
    private EncryptionAlgorithm encryptionAlgorithm;
    private MacAlgorithm macAlgorithm;
    private KeyExchangeAlgorithm keyExchangeAlgorithm;

    private KeySet keySet;

    /** sequence number used for the encryption */
    private long writeSequenceNumber = 0;

    /** sequence number used for the decryption */
    private long readSequenceNumber = 0;

    private byte[] connectionId = null;

    private Boolean encryptThenMac;

    /*public CipherState(
            ProtocolVersion protocolVersion,
            CipherSuite cipherSuite,
            KeySet keySet,
            Boolean encryptThenMac) {
        this.protocolVersion = protocolVersion;
        this.cipherSuite = cipherSuite;
        this.keySet = keySet;
        this.encryptThenMac = encryptThenMac;
        this.connectionId = null;
    }*/

    /*public CipherState(
            ProtocolVersion protocolVersion,
            CipherSuite cipherSuite,
            KeySet keySet,
            Boolean encryptThenMac,
            byte[] connectionId) {
        this.protocolVersion = protocolVersion;
        this.cipherSuite = cipherSuite;
        this.keySet = keySet;
        this.encryptThenMac = encryptThenMac;
        this.connectionId = connectionId;
    }*/

    public CipherState(
            CompressionAlgorithm compressionAlgorithm,
            EncryptionAlgorithm encryptionAlgorithm,
            MacAlgorithm macAlgorithm,
            KeyExchangeAlgorithm keyExchangeAlgorithm,
            KeySet keySet,
            Boolean encryptThenMac,
            byte[] connectionId) {
        this.compressionAlgorithm = compressionAlgorithm;
        this.encryptionAlgorithm = encryptionAlgorithm;
        this.macAlgorithm = macAlgorithm;
        this.keyExchangeAlgorithm = keyExchangeAlgorithm;
        this.keySet = keySet;
        this.encryptThenMac = encryptThenMac;
        this.connectionId = connectionId;
    }

    public Boolean isEncryptThenMac() {
        return encryptThenMac;
    }

    public void setEncryptThenMac(Boolean encryptThenMac) {
        this.encryptThenMac = encryptThenMac;
    }

    public KeySet getKeySet() {
        return keySet;
    }

    public void setKeySet(KeySet keySet) {
        this.keySet = keySet;
    }

    public long getWriteSequenceNumber() {
        return writeSequenceNumber;
    }

    public void setWriteSequenceNumber(long writeSequenceNumber) {
        this.writeSequenceNumber = writeSequenceNumber;
    }

    public void increaseWriteSequenceNumber() {
        writeSequenceNumber += 1;
    }

    public long getReadSequenceNumber() {
        return readSequenceNumber;
    }

    public void setReadSequenceNumber(long readSequenceNumber) {
        this.readSequenceNumber = readSequenceNumber;
    }

    public void increaseReadSequenceNumber() {
        readSequenceNumber += 1;
    }

    public byte[] getConnectionId() {
        return connectionId;
    }

    public void setConnectionId(byte[] connectionId) {
        this.connectionId = connectionId;
    }
}
