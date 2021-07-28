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
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.MessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.EcdhKeyExchangeReplyMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EcdhKeyExchangeReplyMessageParser extends MessageParser<EcdhKeyExchangeReplyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public EcdhKeyExchangeReplyMessageParser(int startPosition, byte[] array) {
        super(startPosition, array);
    }

    private void parseHostKey(EcdhKeyExchangeReplyMessage msg) {
        msg.setHostKeyLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("Host key length: " + msg.getHostKeyLength().getValue());
        msg.setHostKey(parseByteArrayField(msg.getHostKeyLength().getValue()));
        LOGGER.debug("Host key: " + ArrayConverter.bytesToRawHexString(msg.getHostKey().getValue()));
    }

    private void parsePublicKey(EcdhKeyExchangeReplyMessage msg) {
        msg.setEphemeralPublicKeyLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Public key length: " + msg.getEphemeralPublicKeyLength().getValue());
        msg.setEphemeralPublicKey(parseByteArrayField(msg.getEphemeralPublicKeyLength().getValue()));
        LOGGER.debug("Public key: " + ArrayConverter.bytesToRawHexString(msg.getEphemeralPublicKey().getValue()));
    }

    private void parseSignature(EcdhKeyExchangeReplyMessage msg) {
        msg.setSignatureLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Signature length: " + msg.getSignatureLength().getValue());
        msg.setSignature(parseByteArrayField(msg.getSignatureLength().getValue()));
        LOGGER.debug("Signature :" + ArrayConverter.bytesToRawHexString(msg.getSignature().getValue()));
    }

    @Override
    public void parseMessageSpecificPayload(EcdhKeyExchangeReplyMessage msg) {
        parseHostKey(msg);
        parsePublicKey(msg);
        parseSignature(msg);
    }

    @Override
    public EcdhKeyExchangeReplyMessage createMessage() {
        return new EcdhKeyExchangeReplyMessage();
    }
}
