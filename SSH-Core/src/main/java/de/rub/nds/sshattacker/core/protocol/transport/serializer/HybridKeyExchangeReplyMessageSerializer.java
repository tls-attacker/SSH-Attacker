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
import de.rub.nds.sshattacker.core.protocol.transport.message.HybridKeyExchangeReplyMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HybridKeyExchangeReplyMessageSerializer
        extends SshMessageSerializer<HybridKeyExchangeReplyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    protected void serializeMessageSpecificContents(
            HybridKeyExchangeReplyMessage object, SerializerStream output) {
        serializeHostKeyBytes(object, output);
        serializeHybridKey(object, output);
        serializeSignature(object, output);
    }

    private static void serializeHostKeyBytes(
            HybridKeyExchangeReplyMessage object, SerializerStream output) {
        Integer hostKeyBytesLength = object.getHostKeyBytesLength().getValue();
        LOGGER.debug("Host key bytes length: {}", hostKeyBytesLength);
        output.appendInt(hostKeyBytesLength);

        byte[] hostKeyBytes = object.getHostKeyBytes().getValue();
        LOGGER.debug("Host key bytes: {}", () -> ArrayConverter.bytesToRawHexString(hostKeyBytes));
        output.appendBytes(hostKeyBytes);
    }

    private void serializeHybridKey(HybridKeyExchangeReplyMessage object, SerializerStream output) {
        int length = object.getConcatenatedHybridKeysLength().getValue();
        LOGGER.debug("Hybrid Key (server) length: {}", length);
        output.appendInt(length);

        byte[] keys = object.getConcatenatedHybridKeys().getValue();
        LOGGER.debug("Hybrid Key (server): {}", () -> ArrayConverter.bytesToHexString(keys));
        output.appendBytes(keys);
    }

    private static void serializeSignature(
            HybridKeyExchangeReplyMessage object, SerializerStream output) {
        Integer signatureLength = object.getSignatureLength().getValue();
        LOGGER.debug("Signature length: {}", signatureLength);
        output.appendInt(signatureLength);
        output.appendBytes(object.getSignature().getValue());
        LOGGER.debug("Signature: {}", object.getSignature());
    }
}
