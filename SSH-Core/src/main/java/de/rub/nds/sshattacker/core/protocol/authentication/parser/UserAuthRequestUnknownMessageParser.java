/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthRequestUnknownMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthRequestUnknownMessageParser
        extends UserAuthRequestMessageParser<UserAuthRequestUnknownMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UserAuthRequestUnknownMessageParser(byte[] array) {
        super(array);
    }

    public UserAuthRequestUnknownMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public UserAuthRequestUnknownMessage createMessage() {
        return new UserAuthRequestUnknownMessage();
    }

    private void parseMethodSpecificFields() {
        message.setMethodSpecificFields(parseByteArrayField(getBytesLeft()));
        LOGGER.debug(
                "Method Specific Fields: {}",
                ArrayConverter.bytesToHexString(message.getMethodSpecificFields().getValue()));
    }

    @Override
    protected void parseMessageSpecificContents() {
        super.parseMessageSpecificContents();
        parseMethodSpecificFields();
    }
}
