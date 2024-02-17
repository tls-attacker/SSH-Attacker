/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestUnknownMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class GlobalRequestUnknownMessageParser
        extends GlobalRequestMessageParser<GlobalRequestUnknownMessage> {
    private static final Logger LOGGER = LogManager.getLogger();

    /*
        public GlobalRequestUnknownMessageParser(byte[] array) {
            super(array);
        }
        public GlobalRequestUnknownMessageParser(byte[] array, int startPosition) {
            super(array, startPosition);
        }
    */

    public GlobalRequestUnknownMessageParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(GlobalRequestUnknownMessage message) {
        parseProtocolMessageContents(message);
        message.setCompleteResultingMessage(getAlreadyParsed());
    }

    /*@Override
    public GlobalRequestUnknownMessage createMessage() {
        return new GlobalRequestUnknownMessage();
    }*/

    public void parseTypeSpecificData(GlobalRequestUnknownMessage message) {
        message.setTypeSpecificData(parseByteArrayField(getBytesLeft()));
        LOGGER.debug(
                "Type specific data: {}",
                ArrayConverter.bytesToHexString(message.getTypeSpecificData().getValue()));
    }

    @Override
    protected void parseMessageSpecificContents(GlobalRequestUnknownMessage message) {
        super.parseMessageSpecificContents(message);
        parseTypeSpecificData(message);
    }
}
