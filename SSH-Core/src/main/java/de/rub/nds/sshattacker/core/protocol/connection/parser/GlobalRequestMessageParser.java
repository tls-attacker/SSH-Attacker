/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestMessage;
import de.rub.nds.sshattacker.core.util.Converter;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class GlobalRequestMessageParser<T extends GlobalRequestMessage<T>>
        extends SshMessageParser<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    public GlobalRequestMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    private void parseRequestName() {
        message.setRequestNameLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Request name length: " + message.getRequestNameLength().getValue());
        message.setRequestName(
                parseByteString(
                        message.getRequestNameLength().getValue(), StandardCharsets.US_ASCII),
                false);
        LOGGER.debug("Request name: " + message.getRequestName().getValue());
    }

    private void parseWantReply() {
        message.setWantReply(parseByteField(1));
        LOGGER.debug("Want reply: " + Converter.byteToBoolean(message.getWantReply().getValue()));
    }

    @Override
    protected void parseMessageSpecificContents() {
        parseRequestName();
        parseWantReply();
    }
}
