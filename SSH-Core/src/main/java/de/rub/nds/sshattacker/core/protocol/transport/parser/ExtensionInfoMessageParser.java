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
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.ExtensionInfoMessage;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.*;
import de.rub.nds.sshattacker.core.protocol.transport.parser.extension.*;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
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

    private void parseExtensionCount(ExtensionInfoMessage message) {
        message.setExtensionCount(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("Extension count: {}", message.getExtensionCount().getValue());
    }

    private void parseExtensions(ExtensionInfoMessage message) {

        // Commenting just for debugging
        for (int extensionIndex = 0;
                extensionIndex < message.getExtensionCount().getValue();
                extensionIndex++) {
            // Parse extension name to determine the parser to use
            int extensionNameLength = parseIntField(DataFormatConstants.UINT32_SIZE);
            Extension extension =
                    Extension.fromName(
                            parseByteString(extensionNameLength, StandardCharsets.US_ASCII));
            switch (extension) {
                case SERVER_SIG_ALGS:
                    ServerSigAlgsExtension serverSigAlgsExtension = new ServerSigAlgsExtension();
                    serverSigAlgsExtension.getParser(new SshContext(), getStream());
                    message.addExtension(serverSigAlgsExtension);
                    break;
                case DELAY_COMPRESSION:
                    DelayCompressionExtension delayCompressionExtension =
                            new DelayCompressionExtension();
                    delayCompressionExtension.getParser(new SshContext(), getStream());
                    break;
                case PING_OPENSSH_COM:
                    PingExtension pingExtension = new PingExtension();
                    pingExtension.getParser(new SshContext(), getStream());
                    break;
                default:
                    LOGGER.debug(
                            "Extension [{}] (index {}) is unknown or not implemented, parsing as UnknownExtension",
                            extension,
                            extensionIndex);
                    UnknownExtension unknownExtension = new UnknownExtension();
                    unknownExtension.getParser(new SshContext(), getStream());
                    break;
            }
        }
    }

    @Override
    protected void parseMessageSpecificContents(ExtensionInfoMessage message) {
        parseExtensionCount(message);
        parseExtensions(message);
    }
}
