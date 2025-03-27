/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestCancelStreamlocalForwardOpenSshMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class GlobalRequestCancelStreamlocalForwardOpenSshMessageParser
        extends GlobalRequestMessageParser<GlobalRequestCancelStreamlocalForwardOpenSshMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public GlobalRequestCancelStreamlocalForwardOpenSshMessageParser(byte[] array) {
        super(array);
    }

    public GlobalRequestCancelStreamlocalForwardOpenSshMessageParser(
            byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    protected GlobalRequestCancelStreamlocalForwardOpenSshMessage createMessage() {
        return new GlobalRequestCancelStreamlocalForwardOpenSshMessage();
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
