/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer.extension;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.DelayCompressionExtension;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DelayCompressionExtensionSerializer
        extends AbstractExtensionSerializer<DelayCompressionExtension> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DelayCompressionExtensionSerializer(DelayCompressionExtension extension) {
        super(extension);
    }

    @Override
    protected void serializeExtensionValue() {
        serializeCompressionMethodsLength();
        serializeCompressionMethodsClientToServer();
        serializeCompressionMethodsServerToClient();
    }

    private void serializeCompressionMethodsLength() {
        Integer compressionMethodsLength = extension.getCompressionMethodsLength().getValue();
        LOGGER.debug("Compression methods length: {}", compressionMethodsLength);
        appendInt(compressionMethodsLength, DataFormatConstants.STRING_SIZE_LENGTH);
    }

    private void serializeCompressionMethodsClientToServer() {
        Integer compressionMethodsClientToServerLength =
                extension.getCompressionMethodsClientToServerLength().getValue();
        LOGGER.debug(
                "Compression algorithms length (client to server): {}",
                compressionMethodsClientToServerLength);
        appendInt(compressionMethodsClientToServerLength, DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "Compression algorithms (client to server): {}",
                extension.getCompressionMethodsClientToServer().getValue());
        appendString(
                extension.getCompressionMethodsClientToServer().getValue(),
                StandardCharsets.US_ASCII);
    }

    private void serializeCompressionMethodsServerToClient() {
        Integer compressionMethodsServerToClientLength =
                extension.getCompressionMethodsServerToClientLength().getValue();
        LOGGER.debug(
                "Compression algorithms length (server to client): {}",
                compressionMethodsServerToClientLength);
        appendInt(compressionMethodsServerToClientLength, DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "Compression algorithms (server to client): {}",
                extension.getCompressionMethodsServerToClient().getValue());
        appendString(
                extension.getCompressionMethodsServerToClient().getValue(),
                StandardCharsets.US_ASCII);
    }
}
