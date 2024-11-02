/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestX11Message;
import de.rub.nds.sshattacker.core.util.Converter;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelRequestX11MessageParser
        extends ChannelRequestMessageParser<ChannelRequestX11Message> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelRequestX11MessageParser(byte[] array) {
        super(array);
    }

    public ChannelRequestX11MessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public ChannelRequestX11Message createMessage() {
        return new ChannelRequestX11Message();
    }

    private void parseSingleConnection() {
        byte singleConnection = parseByteField(1);
        message.setSingleConnection(singleConnection);
        LOGGER.debug("Single connection: {}", Converter.byteToBoolean(singleConnection));
    }

    private void parseX11AuthenticationProtocol() {
        int x11AuthenticationProtocolLength = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        message.setX11AuthenticationProtocolLength(x11AuthenticationProtocolLength);
        LOGGER.debug("X11 authentication protocol length: {}", x11AuthenticationProtocolLength);
        String x11AuthenticationProtocol =
                parseByteString(x11AuthenticationProtocolLength, StandardCharsets.UTF_8);
        message.setX11AuthenticationProtocol(x11AuthenticationProtocol);
        LOGGER.debug("X11 authentication protocol: {}", x11AuthenticationProtocol);
    }

    private void parseX11AuthenticationCookie() {
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

    private void parseX11ScreenNumber() {
        int x11ScreenNumber = parseIntField(DataFormatConstants.UINT32_SIZE);
        message.setX11ScreenNumber(x11ScreenNumber);
        LOGGER.debug("X11 screen number: {}", x11ScreenNumber);
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
