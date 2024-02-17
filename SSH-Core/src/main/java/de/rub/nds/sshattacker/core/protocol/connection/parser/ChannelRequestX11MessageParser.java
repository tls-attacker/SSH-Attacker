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
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelRequestX11MessageParser
        extends ChannelRequestMessageParser<ChannelRequestX11Message> {

    private static final Logger LOGGER = LogManager.getLogger();

    /*
        public ChannelRequestX11MessageParser(byte[] array) {
            super(array);
        }
        public ChannelRequestX11MessageParser(byte[] array, int startPosition) {
            super(array, startPosition);
        }
    */

    public ChannelRequestX11MessageParser(InputStream stream) {
        super(stream);
    }

    /*
        @Override
        public ChannelRequestX11Message createMessage() {
            return new ChannelRequestX11Message();
        }
    */

    public void parseSingleConnection(ChannelRequestX11Message message) {
        message.setSingleConnection(parseByteField(1));
        LOGGER.debug(
                "Single connection: {}",
                Converter.byteToBoolean(message.getSingleConnection().getValue()));
    }

    public void parseX11AuthenticationProtocol(ChannelRequestX11Message message) {
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

    public void parseX11AuthenticationCookie(ChannelRequestX11Message message) {
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

    public void parseX11ScreenNumber(ChannelRequestX11Message message) {
        message.setX11ScreenNumber(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("X11 screen number: {}", message.getX11ScreenNumber().getValue());
    }

    @Override
    protected void parseMessageSpecificContents(ChannelRequestX11Message message) {
        super.parseMessageSpecificContents(message);
        parseSingleConnection(message);
        parseX11AuthenticationProtocol(message);
        parseX11AuthenticationCookie(message);
        parseX11ScreenNumber(message);
    }

    @Override
    public void parse(ChannelRequestX11Message message) {
        parseProtocolMessageContents(message);
    }
}
