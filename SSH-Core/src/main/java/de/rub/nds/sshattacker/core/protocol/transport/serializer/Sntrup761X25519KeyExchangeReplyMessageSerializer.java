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
import de.rub.nds.sshattacker.core.protocol.transport.message.HybridKeyExchangeReplyMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Sntrup761X25519KeyExchangeReplyMessageSerializer
        extends SshMessageSerializer<HybridKeyExchangeReplyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public Sntrup761X25519KeyExchangeReplyMessageSerializer(
            HybridKeyExchangeReplyMessage message) {
        super(message);
    }

    @Override
    public void serializeMessageSpecificContents() {
        serializeHostKeyBytes();
        serializeHybridKey();
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

    private void serializeHybridKey() {
        appendInt(
                message.getHybridKeyLength().getValue(),
                DataFormatConstants.MPINT_SIZE_LENGTH);
        LOGGER.debug(
                "Hybrid Key (server) length: "
                        + message.getHybridKeyLength().getValue());
        appendBytes(message.getHybridKey().getValue());
        LOGGER.debug(
                "Hybrid Key (server): "
                        + ArrayConverter.bytesToHexString(
                                message.getHybridKey().getValue()));
    }

    private void serializeSignature() {
        appendInt(message.getSignatureLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Signature length: " + message.getSignatureLength().getValue());
        appendBytes(message.getSignature().getValue());
        LOGGER.debug("Signature: " + message.getSignature());
    }
}
