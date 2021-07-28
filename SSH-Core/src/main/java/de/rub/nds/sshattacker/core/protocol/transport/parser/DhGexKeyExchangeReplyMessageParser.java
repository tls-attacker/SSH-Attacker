/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.BinaryPacketConstants;
import de.rub.nds.sshattacker.core.protocol.common.MessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeReplyMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DhGexKeyExchangeReplyMessageParser extends MessageParser<DhGexKeyExchangeReplyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DhGexKeyExchangeReplyMessageParser(int startPosition, byte[] array) {
        super(startPosition, array);
    }

    private void parseHostKey(DhGexKeyExchangeReplyMessage msg) {
        msg.setHostKeyLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("Host key length: " + msg.getHostKeyLength().getValue());
        msg.setHostKey(parseByteArrayField(msg.getHostKeyLength().getValue()));
        LOGGER.debug("Host key: " + ArrayConverter.bytesToRawHexString(msg.getHostKey().getValue()));
    }

    private void parsePublicKey(DhGexKeyExchangeReplyMessage msg) {
        msg.setEphemeralPublicKeyLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("Ephemeral public key length: " + msg.getEphemeralPublicKeyLength().getValue());
        msg.setEphemeralPublicKey(parseBigIntField(msg.getEphemeralPublicKeyLength().getValue()));
        LOGGER.debug("Ephemeral public key: " + msg.getEphemeralPublicKey());
    }

    private void parseSignature(DhGexKeyExchangeReplyMessage msg) {
        msg.setSignatureLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("Signature length: " + msg.getSignatureLength().getValue());
        msg.setSignature(parseByteArrayField(msg.getSignatureLength().getValue()));
        LOGGER.debug("Signature: " + msg.getSignature());
    }

    @Override
    protected void parseMessageSpecificPayload(DhGexKeyExchangeReplyMessage msg) {
        parseHostKey(msg);
        parsePublicKey(msg);
        parseSignature(msg);
    }

    @Override
    public DhGexKeyExchangeReplyMessage createMessage() {
        return new DhGexKeyExchangeReplyMessage();
    }
}
