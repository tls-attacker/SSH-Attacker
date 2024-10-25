/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser.extension;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.DelayCompressionExtension;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DelayCompressionExtensionParser
        extends AbstractExtensionParser<DelayCompressionExtension> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DelayCompressionExtensionParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(DelayCompressionExtension delayCompressionExtension) {
        parseExtensionData(delayCompressionExtension);
    }

    @Override
    protected DelayCompressionExtension createExtension() {
        return new DelayCompressionExtension();
    }

    @Override
    protected void parseExtensionValue(DelayCompressionExtension extension) {
        parseCompressionMethodsLength(extension);
        parseCompressionMethodsClientToServer(extension);
        parseCompressionMethodsServerToClient(extension);
    }

    private void parseCompressionMethodsLength(DelayCompressionExtension extension) {
        extension.setCompressionMethodsLength(
                parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug(
                "Compression methods length: {}",
                extension.getCompressionMethodsLength().getValue());
    }

    private void parseCompressionMethodsClientToServer(DelayCompressionExtension extension) {
        extension.setCompressionMethodsClientToServerLength(
                parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug(
                "Compression algorithms length (client to server): {}",
                extension.getCompressionMethodsClientToServerLength().getValue());
        extension.setCompressionMethodsClientToServer(
                parseByteString(
                        extension.getCompressionMethodsClientToServerLength().getValue(),
                        StandardCharsets.US_ASCII));
        LOGGER.debug(
                "Compression algorithms (client to server): {}",
                extension.getCompressionMethodsClientToServer().getValue());
    }

    private void parseCompressionMethodsServerToClient(DelayCompressionExtension extension) {
        extension.setCompressionMethodsServerToClientLength(
                parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug(
                "Compression algorithms length (server to client): {}",
                extension.getCompressionMethodsServerToClientLength().getValue());
        extension.setCompressionMethodsServerToClient(
                parseByteString(
                        extension.getCompressionMethodsServerToClientLength().getValue(),
                        StandardCharsets.US_ASCII));
        LOGGER.debug(
                "Compression algorithms (server to client): {}",
                extension.getCompressionMethodsServerToClient().getValue());
    }
}
