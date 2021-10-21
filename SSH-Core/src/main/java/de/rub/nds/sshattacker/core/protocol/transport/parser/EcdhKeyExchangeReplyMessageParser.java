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
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.EcdhKeyExchangeReplyMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EcdhKeyExchangeReplyMessageParser
        extends SshMessageParser<EcdhKeyExchangeReplyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public EcdhKeyExchangeReplyMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public EcdhKeyExchangeReplyMessage createMessage() {
        return new EcdhKeyExchangeReplyMessage();
    }

    private void parseHostKey() {
        message.setHostKeyLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("Host key length: " + message.getHostKeyLength().getValue());
        message.setHostKey(parseByteArrayField(message.getHostKeyLength().getValue()));
        LOGGER.debug(
                "Host key: " + ArrayConverter.bytesToRawHexString(message.getHostKey().getValue()));
    }

    private void parsePublicKey() {
        message.setEphemeralPublicKeyLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Public key length: " + message.getEphemeralPublicKeyLength().getValue());
        message.setEphemeralPublicKey(
                parseByteArrayField(message.getEphemeralPublicKeyLength().getValue()));
        LOGGER.debug(
                "Public key: "
                        + ArrayConverter.bytesToRawHexString(
                                message.getEphemeralPublicKey().getValue()));
    }

    private void parseSignature() {
        message.setSignatureLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Signature length: " + message.getSignatureLength().getValue());
        message.setSignature(parseByteArrayField(message.getSignatureLength().getValue()));
        LOGGER.debug(
                "Signature :"
                        + ArrayConverter.bytesToRawHexString(message.getSignature().getValue()));
    }

    @Override
    public void parseMessageSpecificContents() {
        parseHostKey();
        parsePublicKey();
        parseSignature();
    }
}
