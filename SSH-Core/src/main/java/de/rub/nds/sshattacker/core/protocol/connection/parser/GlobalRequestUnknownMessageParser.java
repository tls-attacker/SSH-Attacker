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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class GlobalRequestUnknownMessageParser
        extends GlobalRequestMessageParser<GlobalRequestUnknownMessage> {
    private static final Logger LOGGER = LogManager.getLogger();

    public GlobalRequestUnknownMessageParser(byte[] array) {
        super(array);
    }

    public GlobalRequestUnknownMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public GlobalRequestUnknownMessage createMessage() {
        return new GlobalRequestUnknownMessage();
    }

    private void parseTypeSpecificData() {
        byte[] typeSpecificData = parseByteArrayField(getBytesLeft());
        message.setTypeSpecificData(typeSpecificData);
        LOGGER.debug(
                "TypeSpecificData: {}", () -> ArrayConverter.bytesToHexString(typeSpecificData));
    }

    @Override
    protected void parseMessageSpecificContents() {
        super.parseMessageSpecificContents();
        parseTypeSpecificData();
    }
}
