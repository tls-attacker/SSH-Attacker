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
        Integer hostKeyBytesLength = message.getHostKeyBytesLength().getValue();
        LOGGER.debug("Host key bytes length: {}", hostKeyBytesLength);
        appendInt(hostKeyBytesLength, DataFormatConstants.STRING_SIZE_LENGTH);
        byte[] hostKeyBytes = message.getHostKeyBytes().getValue();
        LOGGER.debug("Host key bytes: {}", () -> ArrayConverter.bytesToRawHexString(hostKeyBytes));
        appendBytes(hostKeyBytes);
    }

    private void serializeEphemeralPublicKey() {
        Integer ephemeralPublicKeyLength = message.getEphemeralPublicKeyLength().getValue();
        LOGGER.debug("Ephemeral public key (server) length: {}", ephemeralPublicKeyLength);
        appendInt(ephemeralPublicKeyLength, DataFormatConstants.MPINT_SIZE_LENGTH);
        appendBytes(message.getEphemeralPublicKey().getValue().toByteArray());
        LOGGER.debug(
                "Ephemeral public key (server): {}", message.getEphemeralPublicKey().getValue());
    }

    private void serializeSignature() {
        Integer signatureLength = message.getSignatureLength().getValue();
        LOGGER.debug("Signature length: {}", signatureLength);
        appendInt(signatureLength, DataFormatConstants.STRING_SIZE_LENGTH);
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
