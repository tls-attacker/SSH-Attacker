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
import de.rub.nds.sshattacker.core.protocol.transport.message.EcdhKeyExchangeReplyMessage;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EcdhKeyExchangeReplyMessageSerializer
        extends SshMessageSerializer<EcdhKeyExchangeReplyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public EcdhKeyExchangeReplyMessageSerializer(EcdhKeyExchangeReplyMessage message) {
        super(message);
    }

    private void serializeHostKeyBytes(EcdhKeyExchangeReplyMessage msg) {
        appendInt(msg.getHostKeyBytesLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Host key bytes length: {}", msg.getHostKeyBytesLength().getValue());
        appendBytes(msg.getHostKeyBytes().getValue());
        LOGGER.debug(
                "Host key bytes: {}",
                ArrayConverter.bytesToRawHexString(msg.getHostKeyBytes().getValue()));
    }

    private void serializeEphemeralPublicKey(EcdhKeyExchangeReplyMessage msg) {
        appendInt(
                msg.getEphemeralPublicKeyLength().getValue(),
                DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "Ephemeral public key (server) length: {}",
                msg.getEphemeralPublicKeyLength().getValue());
        appendBytes(msg.getEphemeralPublicKey().getValue());
        LOGGER.debug("Ephemeral public key (server): {}", msg.getEphemeralPublicKey());
    }

    private void serializeSignature(EcdhKeyExchangeReplyMessage msg) {
        appendInt(msg.getSignatureLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Signature length: {}", msg.getSignatureLength().getValue());
        appendBytes(msg.getSignature().getValue());
        LOGGER.debug("Signature: {}", msg.getSignature());
    }

    @Override
    public void serializeMessageSpecificContents() {
        serializeHostKeyBytes(message);
        serializeEphemeralPublicKey(message);
        serializeSignature(message);
    }
}
