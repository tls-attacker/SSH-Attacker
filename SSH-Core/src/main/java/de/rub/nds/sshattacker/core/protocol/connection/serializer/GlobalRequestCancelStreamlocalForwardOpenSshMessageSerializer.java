/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestCancelStreamlocalForwardOpenSshMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class GlobalRequestCancelStreamlocalForwardOpenSshMessageSerializer
        extends GlobalRequestMessageSerializer<
                GlobalRequestCancelStreamlocalForwardOpenSshMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeSocketPath(
            GlobalRequestCancelStreamlocalForwardOpenSshMessage object, SerializerStream output) {
        Integer socketPathLength = object.getSocketPathLength().getValue();
        LOGGER.debug("Socket path length: {}", socketPathLength);
        output.appendInt(socketPathLength);
        String socketPath = object.getSocketPath().getValue();
        LOGGER.debug("Socket path: {}", () -> backslashEscapeString(socketPath));
        output.appendString(socketPath, StandardCharsets.US_ASCII);
    }

    @Override
    protected void serializeMessageSpecificContents(
            GlobalRequestCancelStreamlocalForwardOpenSshMessage object, SerializerStream output) {
        super.serializeMessageSpecificContents(object, output);
        serializeSocketPath(object, output);
    }
}
