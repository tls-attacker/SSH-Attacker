/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser.extension;

import de.rub.nds.sshattacker.core.protocol.transport.message.extension.DelayCompressionExtension;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DelayCompressionExtensionParser
        extends AbstractExtensionParser<DelayCompressionExtension> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DelayCompressionExtensionParser(byte[] array) {
        super(array);
    }

    public DelayCompressionExtensionParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    protected DelayCompressionExtension createExtension() {
        return new DelayCompressionExtension();
    }

    @Override
    protected void parseExtensionValue() {
        parseCompressionMethodsLength();
        parseCompressionMethodsClientToServer();
        parseCompressionMethodsServerToClient();
    }

    private void parseCompressionMethodsLength() {
        int compressionMethodsLength = parseIntField();
        extension.setCompressionMethodsLength(compressionMethodsLength);
        LOGGER.debug("Compression methods length: {}", compressionMethodsLength);
    }

    private void parseCompressionMethodsClientToServer() {
        int compressionMethodsClientToServerLength = parseIntField();
        extension.setCompressionMethodsClientToServerLength(compressionMethodsClientToServerLength);
        LOGGER.debug(
                "Compression algorithms length (client to server): {}",
                compressionMethodsClientToServerLength);
        String compressionMethodsClientToServer =
                parseByteString(compressionMethodsClientToServerLength, StandardCharsets.US_ASCII);
        extension.setCompressionMethodsClientToServer(compressionMethodsClientToServer);
        LOGGER.debug(
                "Compression algorithms (client to server): {}", compressionMethodsClientToServer);
    }

    private void parseCompressionMethodsServerToClient() {
        int compressionMethodsServerToClientLength = parseIntField();
        extension.setCompressionMethodsServerToClientLength(compressionMethodsServerToClientLength);
        LOGGER.debug(
                "Compression algorithms length (server to client): {}",
                compressionMethodsServerToClientLength);
        String compressionMethodsServerToClient =
                parseByteString(compressionMethodsServerToClientLength, StandardCharsets.US_ASCII);
        extension.setCompressionMethodsServerToClient(compressionMethodsServerToClient);
        LOGGER.debug(
                "Compression algorithms (server to client): {}", compressionMethodsServerToClient);
    }
}
