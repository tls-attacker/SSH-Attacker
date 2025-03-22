/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhKeyExchangeReplyMessage;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DhKeyExchangeReplyMessageSerializer
        extends SshMessageSerializer<DhKeyExchangeReplyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeHostKeyBytes(
            DhKeyExchangeReplyMessage object, SerializerStream output) {
        Integer hostKeyBytesLength = object.getHostKeyBytesLength().getValue();
        LOGGER.debug("Host key length: {}", hostKeyBytesLength);
        output.appendInt(hostKeyBytesLength);
        byte[] hostKeyBytes = object.getHostKeyBytes().getValue();
        LOGGER.debug("Host key: {}", () -> ArrayConverter.bytesToRawHexString(hostKeyBytes));
        output.appendBytes(hostKeyBytes);
    }

    private static void serializeEphemeralPublicKey(
            DhKeyExchangeReplyMessage object, SerializerStream output) {
        Integer ephemeralPublicKeyLength = object.getEphemeralPublicKeyLength().getValue();
        LOGGER.debug("Ephemeral public key (server) length: {}", ephemeralPublicKeyLength);
        output.appendInt(ephemeralPublicKeyLength);
        BigInteger ephemeralPublicKey = object.getEphemeralPublicKey().getValue();
        LOGGER.debug("Ephemeral public key (server): {}", ephemeralPublicKey);
        output.appendBytes(ephemeralPublicKey.toByteArray());
    }

    private static void serializeSignature(
            DhKeyExchangeReplyMessage object, SerializerStream output) {
        Integer signatureLength = object.getSignatureLength().getValue();
        LOGGER.debug("Signature length: {}", signatureLength);
        output.appendInt(signatureLength);
        output.appendBytes(object.getSignature().getValue());
        LOGGER.debug("Signature: {}", object.getSignature());
    }

    @Override
    protected void serializeMessageSpecificContents(
            DhKeyExchangeReplyMessage object, SerializerStream output) {
        serializeHostKeyBytes(object, output);
        serializeEphemeralPublicKey(object, output);
        serializeSignature(object, output);
    }
}
