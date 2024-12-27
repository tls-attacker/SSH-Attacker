/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.BinaryPacketConstants;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.HybridKeyExchangeReplyMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HybridKeyExchangeReplyMessageParser
        extends SshMessageParser<HybridKeyExchangeReplyMessage> {
    private static final Logger LOGGER = LogManager.getLogger();

    public HybridKeyExchangeReplyMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    public HybridKeyExchangeReplyMessageParser(byte[] array) {
        super(array);
    }

    private void parseHostKeyBytes() {
        int hostKeyBytesLength = parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH);
        message.setHostKeyBytesLength(hostKeyBytesLength);
        LOGGER.debug("Host key byte length {}", hostKeyBytesLength);
        byte[] hostKeyBytes = parseByteArrayField(hostKeyBytesLength);
        message.setHostKeyBytes(hostKeyBytes);
        LOGGER.debug("Host key bytes: {}", () -> ArrayConverter.bytesToHexString(hostKeyBytes));
    }

    private void parseHybridKey() {
        int length = parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH);
        LOGGER.debug("ConcatenatedHybridKeys Length: {}", length);
        message.setConcatenatedHybridKeysLength(length);

        byte[] concatenatedHybridKeys = parseByteArrayField(length);
        LOGGER.debug(
                "ConcatenatedHybridKeys: {}",
                () -> ArrayConverter.bytesToRawHexString(concatenatedHybridKeys));
        message.setConcatenatedHybridKeys(concatenatedHybridKeys);
    }

    private void parseSignature() {
        int signatureLength = parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH);
        message.setSignatureLength(signatureLength);
        LOGGER.debug("Signature length: {}", signatureLength);
        byte[] signature = parseByteArrayField(signatureLength);
        message.setSignature(signature);
        LOGGER.debug("Signature: {}", () -> ArrayConverter.bytesToRawHexString(signature));
    }

    @Override
    protected void parseMessageSpecificContents() {
        parseHostKeyBytes();
        parseHybridKey();
        parseSignature();
    }

    @Override
    protected HybridKeyExchangeReplyMessage createMessage() {
        return new HybridKeyExchangeReplyMessage();
    }
}
