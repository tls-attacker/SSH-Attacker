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
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.EcdhKeyExchangeReplyMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EcdhKeyExchangeReplyMessageSerializer
        extends SshMessageSerializer<EcdhKeyExchangeReplyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeHostKeyBytes(
            EcdhKeyExchangeReplyMessage object, SerializerStream output) {
        Integer hostKeyBytesLength = object.getHostKeyBytesLength().getValue();
        LOGGER.debug("Host key bytes length: {}", hostKeyBytesLength);
        output.appendInt(hostKeyBytesLength, DataFormatConstants.STRING_SIZE_LENGTH);
        byte[] hostKeyBytes = object.getHostKeyBytes().getValue();
        LOGGER.debug("Host key bytes: {}", () -> ArrayConverter.bytesToRawHexString(hostKeyBytes));
        output.appendBytes(hostKeyBytes);
    }

    private static void serializeEphemeralPublicKey(
            EcdhKeyExchangeReplyMessage object, SerializerStream output) {
        Integer ephemeralPublicKeyLength = object.getEphemeralPublicKeyLength().getValue();
        LOGGER.debug("Ephemeral public key (server) length: {}", ephemeralPublicKeyLength);
        output.appendInt(ephemeralPublicKeyLength, DataFormatConstants.STRING_SIZE_LENGTH);
        output.appendBytes(object.getEphemeralPublicKey().getValue());
        LOGGER.debug("Ephemeral public key (server): {}", object.getEphemeralPublicKey());
    }

    private static void serializeSignature(
            EcdhKeyExchangeReplyMessage object, SerializerStream output) {
        Integer signatureLength = object.getSignatureLength().getValue();
        LOGGER.debug("Signature length: {}", signatureLength);
        output.appendInt(signatureLength, DataFormatConstants.STRING_SIZE_LENGTH);
        output.appendBytes(object.getSignature().getValue());
        LOGGER.debug("Signature: {}", object.getSignature());
    }

    @Override
    protected void serializeMessageSpecificContents(
            EcdhKeyExchangeReplyMessage object, SerializerStream output) {
        serializeHostKeyBytes(object, output);
        serializeEphemeralPublicKey(object, output);
        serializeSignature(object, output);
    }
}
