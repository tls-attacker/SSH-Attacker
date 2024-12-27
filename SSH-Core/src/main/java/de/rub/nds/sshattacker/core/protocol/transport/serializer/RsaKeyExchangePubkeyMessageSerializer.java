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
import de.rub.nds.sshattacker.core.protocol.transport.message.RsaKeyExchangePubkeyMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RsaKeyExchangePubkeyMessageSerializer
        extends SshMessageSerializer<RsaKeyExchangePubkeyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeHostKeyBytes(
            RsaKeyExchangePubkeyMessage object, SerializerStream output) {
        Integer hostKeyBytesLength = object.getHostKeyBytesLength().getValue();
        LOGGER.debug("Host key bytes length: {}", hostKeyBytesLength);
        output.appendInt(hostKeyBytesLength, DataFormatConstants.STRING_SIZE_LENGTH);

        byte[] hostKeyBytes = object.getHostKeyBytes().getValue();
        LOGGER.debug("Host key bytes: {}", () -> ArrayConverter.bytesToRawHexString(hostKeyBytes));
        output.appendBytes(hostKeyBytes);
    }

    private static void serializeTransientPublicKeyBytes(
            RsaKeyExchangePubkeyMessage object, SerializerStream output) {
        Integer transientPublicKeyBytesLength =
                object.getTransientPublicKeyBytesLength().getValue();
        LOGGER.debug("Transient public key length: {}", transientPublicKeyBytesLength);
        output.appendInt(transientPublicKeyBytesLength, DataFormatConstants.STRING_SIZE_LENGTH);

        byte[] transientPublicKeyBytes = object.getTransientPublicKeyBytes().getValue();
        LOGGER.debug(
                "Transient public key: {}",
                () -> ArrayConverter.bytesToRawHexString(transientPublicKeyBytes));
        output.appendBytes(transientPublicKeyBytes);
    }

    @Override
    protected void serializeMessageSpecificContents(
            RsaKeyExchangePubkeyMessage object, SerializerStream output) {
        serializeHostKeyBytes(object, output);
        serializeTransientPublicKeyBytes(object, output);
    }
}
