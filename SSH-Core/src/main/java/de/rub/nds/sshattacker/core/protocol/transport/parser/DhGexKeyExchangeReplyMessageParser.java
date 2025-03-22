/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeReplyMessage;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DhGexKeyExchangeReplyMessageParser
        extends SshMessageParser<DhGexKeyExchangeReplyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DhGexKeyExchangeReplyMessageParser(byte[] array) {
        super(array);
    }

    public DhGexKeyExchangeReplyMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public DhGexKeyExchangeReplyMessage createMessage() {
        return new DhGexKeyExchangeReplyMessage();
    }

    private void parseHostKeyBytes() {
        int hostKeyBytesLength = parseIntField();
        message.setHostKeyBytesLength(hostKeyBytesLength);
        LOGGER.debug("Host key bytes length: {}", hostKeyBytesLength);
        byte[] hostKeyBytes = parseByteArrayField(hostKeyBytesLength);
        message.setHostKeyBytes(hostKeyBytes);
        LOGGER.debug("Host key bytes: {}", () -> ArrayConverter.bytesToRawHexString(hostKeyBytes));
    }

    private void parseEphemeralPublicKey() {
        int ephemeralPublicKeyLength = parseIntField();
        message.setEphemeralPublicKeyLength(ephemeralPublicKeyLength);
        LOGGER.debug("Ephemeral public key (server) length: {}", ephemeralPublicKeyLength);
        BigInteger ephemeralPublicKey = parseBigIntField(ephemeralPublicKeyLength);
        message.setEphemeralPublicKey(ephemeralPublicKey);
        LOGGER.debug("Ephemeral public key (server): {}", ephemeralPublicKey);
    }

    private void parseSignature() {
        int signatureLength = parseIntField();
        message.setSignatureLength(signatureLength);
        LOGGER.debug("Signature length: {}", signatureLength);
        byte[] signature = parseByteArrayField(signatureLength);
        message.setSignature(signature);
        LOGGER.debug("Signature: {}", () -> ArrayConverter.bytesToRawHexString(signature));
    }

    @Override
    protected void parseMessageSpecificContents() {
        parseHostKeyBytes();
        parseEphemeralPublicKey();
        parseSignature();
    }
}
