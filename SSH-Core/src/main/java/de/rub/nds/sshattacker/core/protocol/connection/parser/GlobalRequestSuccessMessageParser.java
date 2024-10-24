/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestSuccessMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class GlobalRequestSuccessMessageParser
        extends SshMessageParser<GlobalRequestSuccessMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public GlobalRequestSuccessMessageParser(byte[] array) {
        super(array);
    }

    public GlobalRequestSuccessMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    private void parseResponseSpecificData() {
        message.setResponseSpecificData(parseByteArrayField(getBytesLeft()));
        LOGGER.debug(
                "Response specific data blob: {}",
                ArrayConverter.bytesToRawHexString(message.getResponseSpecificData().getValue()));
    }

    @Override
    public GlobalRequestSuccessMessage createMessage() {
        return new GlobalRequestSuccessMessage();
    }

    @Override
    protected void parseMessageSpecificContents() {
        parseResponseSpecificData();
    }
}
