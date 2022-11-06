/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.Sntrup761X25519KeyExchangeReplyMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Sntrup761X25519KeyExchangeReplyMessageSerializer
        extends SshMessageSerializer<Sntrup761X25519KeyExchangeReplyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public Sntrup761X25519KeyExchangeReplyMessageSerializer(
            Sntrup761X25519KeyExchangeReplyMessage message) {
        super(message);
    }

    @Override
    public void serializeMessageSpecificContents() {
        serializeHostKeyBytes();
        serializeMultiPrecisionInteger();
        serializeSignature();
    }

    private void serializeHostKeyBytes() {
        appendInt(
                message.getHostKeyBytesLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Host key bytes length: " + message.getHostKeyBytesLength().getValue());

        appendBytes(message.getHostKeyBytes().getValue());
        LOGGER.debug(
                "Host key bytes: "
                        + ArrayConverter.bytesToRawHexString(message.getHostKeyBytes().getValue()));
    }

    private void serializeMultiPrecisionInteger() {
        appendInt(
                message.getMultiPrecisionIntegerLength().getValue(),
                DataFormatConstants.MPINT_SIZE_LENGTH);
        LOGGER.debug(
                "Multi Precision Integer (server) length: "
                        + message.getMultiPrecisionIntegerLength().getValue());
        appendBytes(message.getMultiPrecisionInteger().getValue());
        LOGGER.debug(
                "Multi Precision Integer (server): "
                        + ArrayConverter.bytesToHexString(
                                message.getMultiPrecisionInteger().getValue()));
    }

    private void serializeSignature() {
        appendInt(message.getSignatureLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Signature length: " + message.getSignatureLength().getValue());
        appendBytes(message.getSignature().getValue());
        LOGGER.debug("Signature: " + message.getSignature());
    }
}
