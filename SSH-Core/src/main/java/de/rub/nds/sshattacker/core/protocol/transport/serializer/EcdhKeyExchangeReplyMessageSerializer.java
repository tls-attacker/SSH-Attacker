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
        Integer hostKeyBytesLength = msg.getHostKeyBytesLength().getValue();
        LOGGER.debug("Host key bytes length: {}", hostKeyBytesLength);
        appendInt(hostKeyBytesLength, DataFormatConstants.STRING_SIZE_LENGTH);
        byte[] hostKeyBytes = msg.getHostKeyBytes().getValue();
        LOGGER.debug("Host key bytes: {}", () -> ArrayConverter.bytesToRawHexString(hostKeyBytes));
        appendBytes(hostKeyBytes);
    }

    private void serializeEphemeralPublicKey(EcdhKeyExchangeReplyMessage msg) {
        Integer ephemeralPublicKeyLength = msg.getEphemeralPublicKeyLength().getValue();
        LOGGER.debug("Ephemeral public key (server) length: {}", ephemeralPublicKeyLength);
        appendInt(ephemeralPublicKeyLength, DataFormatConstants.STRING_SIZE_LENGTH);
        appendBytes(msg.getEphemeralPublicKey().getValue());
        LOGGER.debug("Ephemeral public key (server): {}", msg.getEphemeralPublicKey());
    }

    private void serializeSignature(EcdhKeyExchangeReplyMessage msg) {
        Integer signatureLength = msg.getSignatureLength().getValue();
        LOGGER.debug("Signature length: {}", signatureLength);
        appendInt(signatureLength, DataFormatConstants.STRING_SIZE_LENGTH);
        appendBytes(msg.getSignature().getValue());
        LOGGER.debug("Signature: {}", msg.getSignature());
    }

    @Override
    protected void serializeMessageSpecificContents() {
        serializeHostKeyBytes(message);
        serializeEphemeralPublicKey(message);
        serializeSignature(message);
    }
}
