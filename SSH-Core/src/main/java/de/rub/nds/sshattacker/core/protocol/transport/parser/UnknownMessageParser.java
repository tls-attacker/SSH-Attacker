/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.UnknownMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UnknownMessageParser extends SshMessageParser<UnknownMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    /*
        public UnknownMessageParser(byte[] array) {
            super(array);
        }

        public UnknownMessageParser(byte[] array, int startPosition) {
            super(array, startPosition);
        }
    */

    public UnknownMessageParser(InputStream stream) {
        super(stream);
    }

    /*
        @Override
        public UnknownMessage createMessage() {
            return new UnknownMessage();
        }
    */

    @Override
    protected void parseMessageSpecificContents(UnknownMessage message) {
        message.setPayload(parseArrayOrTillEnd(-1));
        LOGGER.debug(
                "Payload: " + ArrayConverter.bytesToRawHexString(message.getPayload().getValue()));
    }

    @Override
    public void parse(UnknownMessage message) {
        parseMessageSpecificContents(message);
    }
}
