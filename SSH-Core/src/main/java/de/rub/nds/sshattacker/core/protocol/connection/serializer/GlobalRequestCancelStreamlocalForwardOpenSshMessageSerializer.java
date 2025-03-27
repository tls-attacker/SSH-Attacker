/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestCancelStreamlocalForwardOpenSshMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class GlobalRequestCancelStreamlocalForwardOpenSshMessageSerializer
        extends GlobalRequestMessageSerializer<
                GlobalRequestCancelStreamlocalForwardOpenSshMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public GlobalRequestCancelStreamlocalForwardOpenSshMessageSerializer(
            GlobalRequestCancelStreamlocalForwardOpenSshMessage message) {
        super(message);
    }

    private void serializeSocketPath() {
        LOGGER.debug("Socket path length: {}", message.getSocketPathLength().getValue());
        appendInt(message.getSocketPathLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Socket path: {}", message.getSocketPath().getValue());
        appendString(message.getSocketPath().getValue(), StandardCharsets.US_ASCII);
    }

    @Override
    public void serializeMessageSpecificContents() {
        super.serializeMessageSpecificContents();
        serializeSocketPath();
    }
}
