/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestX11ReqMessage;
import de.rub.nds.sshattacker.core.util.Converter;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelRequestX11ReqMessageParser
        extends ChannelRequestMessageParser<ChannelRequestX11ReqMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelRequestX11ReqMessageParser(byte[] array) {
        super(array);
    }

    public ChannelRequestX11ReqMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public ChannelRequestX11ReqMessage createMessage() {
        return new ChannelRequestX11ReqMessage();
    }

    public void parseSingleConnection() {
        message.setSingleConnection(parseByteField(1));
        LOGGER.debug(
                "Single connection: {}",
                Converter.byteToBoolean(message.getSingleConnection().getValue()));
    }

    public void parseX11AuthenticationProtocol() {
        message.setX11AuthenticationProtocolLength(
                parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug(
                "X11 authentication protocol length: {}",
                message.getX11AuthenticationProtocolLength().getValue());
        message.setX11AuthenticationProtocol(
                parseByteString(
                        message.getX11AuthenticationProtocolLength().getValue(),
                        StandardCharsets.UTF_8));
        LOGGER.debug(
                "X11 authentication protocol: {}",
                message.getX11AuthenticationProtocol().getValue());
    }

    public void parseX11AuthenticationCookie() {
        message.setX11AuthenticationCookieLength(
                parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug(
                "X11 authentication cookie length: {}", message.getX11AuthenticationCookieLength());
        message.setX11AuthenticationCookie(
                parseByteString(
                        message.getX11AuthenticationCookieLength().getValue(),
                        StandardCharsets.UTF_8));
        LOGGER.debug(
                "X11 authentication cookie: {}", message.getX11AuthenticationCookie().getValue());
    }

    public void parseX11ScreenNumber() {
        message.setX11ScreenNumber(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("X11 screen number: {}", message.getX11ScreenNumber().getValue());
    }

    @Override
    protected void parseMessageSpecificContents() {
        super.parseMessageSpecificContents();
        parseSingleConnection();
        parseX11AuthenticationProtocol();
        parseX11AuthenticationCookie();
        parseX11ScreenNumber();
    }
}
