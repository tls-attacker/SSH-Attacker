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
        message.setHostKeyBytesLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("Host key byte length{}", message.getHostKeyBytesLength());
        message.setHostKeyBytes(parseByteArrayField(message.getHostKeyBytesLength().getValue()));
        LOGGER.debug(
                "Host key bytes: {}",
                ArrayConverter.bytesToHexString(message.getHostKeyBytes().getValue()));
    }

    private void parsePublicValues() {
        message.setPublicValuesLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("Public values length: {}", message.getPublicValuesLength().getValue());
        message.setPublicValues(parseByteArrayField(message.getPublicValuesLength().getValue()));
        LOGGER.debug("Public values: {}", message.getPublicValues());
    }

    private void parseSignature() {
        message.setSignatureLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("Signature length: {}", message.getSignatureLength().getValue());
        message.setSignature(parseByteArrayField(message.getSignatureLength().getValue()));
        LOGGER.debug("Signature: {}", message.getSignature());
    }

    @Override
    protected void parseMessageSpecificContents() {
        parseHostKeyBytes();
        parsePublicValues();
        parseSignature();
    }

    @Override
    protected HybridKeyExchangeReplyMessage createMessage() {
        return new HybridKeyExchangeReplyMessage();
    }
}
