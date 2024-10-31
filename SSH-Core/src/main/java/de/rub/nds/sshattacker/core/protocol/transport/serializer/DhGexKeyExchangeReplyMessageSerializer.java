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
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeReplyMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DhGexKeyExchangeReplyMessageSerializer
        extends SshMessageSerializer<DhGexKeyExchangeReplyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DhGexKeyExchangeReplyMessageSerializer(DhGexKeyExchangeReplyMessage message) {
        super(message);
    }

    private void serializeHostKeyBytes() {
        appendInt(
                message.getHostKeyBytesLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Host key bytes length: {}", message.getHostKeyBytesLength().getValue());
        appendBytes(message.getHostKeyBytes().getValue());
        LOGGER.debug(
                "Host key bytes: {}",
                () -> ArrayConverter.bytesToRawHexString(message.getHostKeyBytes().getValue()));
    }

    private void serializeEphemeralPublicKey() {
        appendInt(
                message.getEphemeralPublicKeyLength().getValue(),
                DataFormatConstants.MPINT_SIZE_LENGTH);
        LOGGER.debug(
                "Ephemeral public key (server) length: {}",
                message.getEphemeralPublicKeyLength().getValue());
        appendBytes(message.getEphemeralPublicKey().getValue().toByteArray());
        LOGGER.debug(
                "Ephemeral public key (server): {}", message.getEphemeralPublicKey().getValue());
    }

    private void serializeSignature() {
        appendInt(message.getSignatureLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Signature length: {}", message.getSignatureLength().getValue());
        appendBytes(message.getSignature().getValue());
        LOGGER.debug("Signature: {}", message.getSignature());
    }

    @Override
    protected void serializeMessageSpecificContents() {
        serializeHostKeyBytes();
        serializeEphemeralPublicKey();
        serializeSignature();
    }
}
