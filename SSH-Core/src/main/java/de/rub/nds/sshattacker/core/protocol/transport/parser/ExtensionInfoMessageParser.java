/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.ExtensionInfoMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ExtensionInfoMessageParser extends SshMessageParser<ExtensionInfoMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ExtensionInfoMessageParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(ExtensionInfoMessage message) {
        parseMessageSpecificContents(message);
    }

    /*public ExtensionInfoMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }*/

    /*    @Override
    public ExtensionInfoMessage createMessage() {
        return new ExtensionInfoMessage();
    }*/

    private void parseExtensionCount(ExtensionInfoMessage message) {
        message.setExtensionCount(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("Extension count: {}", message.getExtensionCount().getValue());
    }

    private void parseExtensions(ExtensionInfoMessage message) {
        // Commenting just for debugging
        /*for (int extensionIndex = 0, extensionStartPointer = getPointer();
                extensionIndex < message.getExtensionCount().getValue();
                extensionIndex++, extensionStartPointer = getPointer()) {
            // Parse extension name to determine the parser to use
            int extensionNameLength = parseIntField(DataFormatConstants.UINT32_SIZE);
            Extension extension =
                    Extension.fromName(
                            parseByteString(extensionNameLength, StandardCharsets.US_ASCII));
            AbstractExtensionParser<?> extensionParser;
            switch (extension) {
                case SERVER_SIG_ALGS:
                    extensionParser =
                            new ServerSigAlgsExtensionParser(getArray(), extensionStartPointer);
                    break;
                case DELAY_COMPRESSION:
                    extensionParser =
                            new DelayCompressionExtensionParser(getArray(), extensionStartPointer);
                    break;
                case PING_OPENSSH_COM:
                    extensionParser = new PingExtensionParser(getArray(), extensionStartPointer);
                    break;
                default:
                    LOGGER.debug(
                            "Extension [{}] (index {}) is unknown or not implemented, parsing as UnknownExtension",
                            extension,
                            extensionIndex);
                    extensionParser = new UnknownExtensionParser(getArray(), extensionStartPointer);
                    break;
            }
            message.addExtension(extensionParser.parse());
            setPointer(extensionParser.getPointer());
        }*/
    }

    @Override
    protected void parseMessageSpecificContents(ExtensionInfoMessage message) {
        parseExtensionCount(message);
        parseExtensions(message);
    }
}
