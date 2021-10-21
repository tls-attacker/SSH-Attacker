/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.BinaryPacketConstants;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeReplyMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DhGexKeyExchangeReplyMessageParser
        extends SshMessageParser<DhGexKeyExchangeReplyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DhGexKeyExchangeReplyMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public DhGexKeyExchangeReplyMessage createMessage() {
        return new DhGexKeyExchangeReplyMessage();
    }

    private void parseHostKey() {
        message.setHostKeyLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("Host key length: " + message.getHostKeyLength().getValue());
        message.setHostKey(parseByteArrayField(message.getHostKeyLength().getValue()));
        LOGGER.debug(
                "Host key: " + ArrayConverter.bytesToRawHexString(message.getHostKey().getValue()));
    }

    private void parsePublicKey() {
        message.setEphemeralPublicKeyLength(
                parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug(
                "Ephemeral public key length: " + message.getEphemeralPublicKeyLength().getValue());
        message.setEphemeralPublicKey(
                parseBigIntField(message.getEphemeralPublicKeyLength().getValue()));
        LOGGER.debug("Ephemeral public key: " + message.getEphemeralPublicKey());
    }

    private void parseSignature() {
        message.setSignatureLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("Signature length: " + message.getSignatureLength().getValue());
        message.setSignature(parseByteArrayField(message.getSignatureLength().getValue()));
        LOGGER.debug("Signature: " + message.getSignature());
    }

    @Override
    protected void parseMessageSpecificContents() {
        parseHostKey();
        parsePublicKey();
        parseSignature();
    }
}
