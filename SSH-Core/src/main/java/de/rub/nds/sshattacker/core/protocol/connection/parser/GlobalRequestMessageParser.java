/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.MessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestMessage;
import de.rub.nds.sshattacker.core.util.Converter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class GlobalRequestMessageParser<T extends GlobalRequestMessage<T>> extends MessageParser<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    public GlobalRequestMessageParser(int startPosition, byte[] array) {
        super(startPosition, array);
    }

    private void parseRequestName(T msg) {
        msg.setRequestNameLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Request name length: " + msg.getRequestNameLength().getValue());
        msg.setRequestName(parseByteString(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH)), false);
        LOGGER.debug("Request name: " + msg.getRequestName().getValue());
    }

    private void parseWantReply(T msg) {
        msg.setWantReply(parseByteField(1));
        LOGGER.debug("Want reply: " + Converter.byteToBoolean(msg.getWantReply().getValue()));
    }

    @Override
    protected void parseMessageSpecificPayload(T msg) {
        parseRequestName(msg);
        parseWantReply(msg);
    }

}
