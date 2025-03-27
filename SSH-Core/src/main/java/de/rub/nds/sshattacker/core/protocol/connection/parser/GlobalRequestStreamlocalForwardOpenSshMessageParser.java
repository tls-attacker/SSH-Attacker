/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestStreamlocalForwardOpenSshMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class GlobalRequestStreamlocalForwardOpenSshMessageParser
        extends GlobalRequestMessageParser<GlobalRequestStreamlocalForwardOpenSshMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public GlobalRequestStreamlocalForwardOpenSshMessageParser(byte[] array) {
        super(array);
    }

    public GlobalRequestStreamlocalForwardOpenSshMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    protected GlobalRequestStreamlocalForwardOpenSshMessage createMessage() {
        return new GlobalRequestStreamlocalForwardOpenSshMessage();
    }

    public void parseSocketPath() {
        message.setSocketPathLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Socket path length: {}", message.getSocketPathLength().getValue());
        message.setSocketPath(
                parseByteString(
                        message.getSocketPathLength().getValue(), StandardCharsets.US_ASCII));
        LOGGER.debug("Socket path: {}", message.getSocketPath().getValue());
    }

    @Override
    protected void parseMessageSpecificContents() {
        super.parseMessageSpecificContents();
        parseSocketPath();
    }
}
