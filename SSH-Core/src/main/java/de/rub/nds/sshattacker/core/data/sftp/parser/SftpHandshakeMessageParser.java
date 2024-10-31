/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.SftpMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.message.SftpHandshakeMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.extension.SftpAbstractExtensionParser;
import de.rub.nds.sshattacker.core.data.sftp.parser.extension.SftpUnknownExtensionParser;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class SftpHandshakeMessageParser<T extends SftpHandshakeMessage<T>>
        extends SftpMessageParser<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected SftpHandshakeMessageParser(byte[] array) {
        super(array);
    }

    protected SftpHandshakeMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    private void parseVersion() {
        message.setVersion(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("Version: {}", message.getVersion().getValue());
    }

    private void parseExtensions() {
        int extensionStartPointer;
        int extensionIndex = 0;
        while (getBytesLeft() > 0) {
            extensionStartPointer = getPointer();
            // Parse extension name to determine the parser to use
            int extensionNameLength = parseIntField(DataFormatConstants.UINT32_SIZE);
            SftpExtension extension =
                    SftpExtension.fromName(
                            parseByteString(extensionNameLength, StandardCharsets.US_ASCII));
            SftpAbstractExtensionParser<?> extensionParser;
            switch (extension) {
                default:
                    LOGGER.debug(
                            "Extension [{}] (index {}) is unknown or not implemented, parsing as UnknownExtension",
                            extension,
                            extensionIndex);
                    extensionParser =
                            new SftpUnknownExtensionParser(getArray(), extensionStartPointer);
                    break;
            }
            message.addExtension(extensionParser.parse());
            setPointer(extensionParser.getPointer());
            extensionIndex++;
        }
    }

    @Override
    protected void parseMessageSpecificContents() {
        parseVersion();
        parseExtensions();
    }
}
