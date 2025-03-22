/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer.extension;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.DelayCompressionExtension;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DelayCompressionExtensionSerializer
        extends AbstractExtensionSerializer<DelayCompressionExtension> {

    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    protected void serializeExtensionValue(
            DelayCompressionExtension object, SerializerStream output) {
        serializeCompressionMethodsLength(object, output);
        serializeCompressionMethodsClientToServer(object, output);
        serializeCompressionMethodsServerToClient(object, output);
    }

    private static void serializeCompressionMethodsLength(
            DelayCompressionExtension object, SerializerStream output) {
        Integer compressionMethodsLength = object.getCompressionMethodsLength().getValue();
        LOGGER.debug("Compression methods length: {}", compressionMethodsLength);
        output.appendInt(compressionMethodsLength);
    }

    private static void serializeCompressionMethodsClientToServer(
            DelayCompressionExtension object, SerializerStream output) {
        Integer compressionMethodsClientToServerLength =
                object.getCompressionMethodsClientToServerLength().getValue();
        LOGGER.debug(
                "Compression algorithms length (client to server): {}",
                compressionMethodsClientToServerLength);
        output.appendInt(compressionMethodsClientToServerLength);
        String compressionMethodsClientToServer =
                object.getCompressionMethodsClientToServer().getValue();
        LOGGER.debug(
                "Compression algorithms (client to server): {}",
                () -> backslashEscapeString(compressionMethodsClientToServer));
        output.appendString(compressionMethodsClientToServer, StandardCharsets.US_ASCII);
    }

    private static void serializeCompressionMethodsServerToClient(
            DelayCompressionExtension object, SerializerStream output) {
        Integer compressionMethodsServerToClientLength =
                object.getCompressionMethodsServerToClientLength().getValue();
        LOGGER.debug(
                "Compression algorithms length (server to client): {}",
                compressionMethodsServerToClientLength);
        output.appendInt(compressionMethodsServerToClientLength);
        String compressionMethodsServerToClient =
                object.getCompressionMethodsServerToClient().getValue();
        LOGGER.debug(
                "Compression algorithms (server to client): {}",
                () -> backslashEscapeString(compressionMethodsServerToClient));
        output.appendString(compressionMethodsServerToClient, StandardCharsets.US_ASCII);
    }
}
