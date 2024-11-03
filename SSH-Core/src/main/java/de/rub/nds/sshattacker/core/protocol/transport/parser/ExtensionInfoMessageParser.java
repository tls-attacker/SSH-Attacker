/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.constants.Extension;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.ExtensionInfoMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.extension.*;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ExtensionInfoMessageParser extends SshMessageParser<ExtensionInfoMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ExtensionInfoMessageParser(byte[] array) {
        super(array);
    }

    public ExtensionInfoMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public ExtensionInfoMessage createMessage() {
        return new ExtensionInfoMessage();
    }

    private void parseExtensionCount() {
        int extensionCount = parseIntField(DataFormatConstants.UINT32_SIZE);
        message.setExtensionCount(extensionCount);
        LOGGER.debug("Extension count: {}", extensionCount);
    }

    private void parseExtensions() {
        for (int extensionIndex = 0, extensionStartPointer = getPointer();
                extensionIndex < message.getExtensionCount().getValue();
                extensionIndex++, extensionStartPointer = getPointer()) {

            // Extrahiere den Namen der Erweiterung
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
                case PUBLICKEY_ALGORITHMS_ROUMENPETROV:
                    extensionParser =
                            new PublicKeyAlgorithmsRoumenPetrovExtensionParser(
                                    getArray(), extensionStartPointer);
                    break;
                default:
                    LOGGER.debug(
                            "Extension [{}] (index {}) is unknown or not implemented, parsing as UnknownExtension",
                            extension,
                            extensionIndex);
                    extensionParser = new UnknownExtensionParser(getArray(), extensionStartPointer);
                    break;
            }

            // Erweiterung hinzufügen
            message.addExtension(extensionParser.parse());
            setPointer(extensionParser.getPointer());
        }
    }

    @Override
    protected void parseMessageSpecificContents() {
        parseExtensionCount();
        parseExtensions();
    }
}
