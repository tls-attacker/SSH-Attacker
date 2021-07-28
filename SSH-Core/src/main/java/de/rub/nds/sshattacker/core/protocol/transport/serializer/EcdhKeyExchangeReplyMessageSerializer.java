/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.MessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.EcdhKeyExchangeReplyMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EcdhKeyExchangeReplyMessageSerializer extends MessageSerializer<EcdhKeyExchangeReplyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public EcdhKeyExchangeReplyMessageSerializer(EcdhKeyExchangeReplyMessage msg) {
        super(msg);
    }

    private void serializeHostKey(EcdhKeyExchangeReplyMessage msg) {
        appendInt(msg.getHostKeyLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Host key length: " + msg.getHostKeyLength().getValue());
        appendBytes(msg.getHostKey().getValue());
        LOGGER.debug("Host key: " + ArrayConverter.bytesToRawHexString(msg.getHostKey().getValue()));
    }

    private void serializePublicKey(EcdhKeyExchangeReplyMessage msg) {
        appendInt(msg.getEphemeralPublicKeyLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Public key length: " + msg.getEphemeralPublicKeyLength().getValue());
        appendBytes(msg.getEphemeralPublicKey().getValue());
        LOGGER.debug("Public key: " + msg.getEphemeralPublicKey());
    }

    private void serializeSignature(EcdhKeyExchangeReplyMessage msg) {
        appendInt(msg.getSignatureLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Signature length: " + msg.getSignatureLength().getValue());
        appendBytes(msg.getSignature().getValue());
        LOGGER.debug("Signature: " + msg.getSignature());
    }

    @Override
    public void serializeMessageSpecificPayload() {
        serializeHostKey(msg);
        serializePublicKey(msg);
        serializeSignature(msg);
    }
}
