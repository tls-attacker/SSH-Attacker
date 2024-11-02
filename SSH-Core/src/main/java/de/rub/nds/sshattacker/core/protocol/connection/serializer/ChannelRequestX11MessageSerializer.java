/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestX11Message;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelRequestX11MessageSerializer
        extends ChannelRequestMessageSerializer<ChannelRequestX11Message> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelRequestX11MessageSerializer(ChannelRequestX11Message message) {
        super(message);
    }

    private void serializeSingleConnection() {
        LOGGER.debug("Single connection: {}", message.getSingleConnection().getValue());
        appendByte(message.getSingleConnection().getValue());
    }

    private void serializeX11AuthenticationProtocol() {
        Integer x11AuthenticationProtocolLength =
                message.getX11AuthenticationProtocolLength().getValue();
        LOGGER.debug("X11 authentication protocol length: {}", x11AuthenticationProtocolLength);
        appendInt(x11AuthenticationProtocolLength, DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "X11 authentication protocol: {}",
                message.getX11AuthenticationProtocol().getValue());
        appendString(message.getX11AuthenticationProtocol().getValue(), StandardCharsets.UTF_8);
    }

    private void serializeX11AuthenticationCookie() {
        Integer x11AuthenticationCookieLength =
                message.getX11AuthenticationCookieLength().getValue();
        LOGGER.debug("X11 authenticaton cookie length: {}", x11AuthenticationCookieLength);
        appendInt(x11AuthenticationCookieLength, DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "X11 authentication cookie: {}", message.getX11AuthenticationCookie().getValue());
        appendString(message.getX11AuthenticationCookie().getValue(), StandardCharsets.UTF_8);
    }

    private void serializeX11ScreenNumber() {
        Integer x11ScreenNumber = message.getX11ScreenNumber().getValue();
        LOGGER.debug("X11 screen number: {}", x11ScreenNumber);
        appendInt(x11ScreenNumber, DataFormatConstants.UINT32_SIZE);
    }

    @Override
    protected void serializeMessageSpecificContents() {
        super.serializeMessageSpecificContents();
        serializeSingleConnection();
        serializeX11AuthenticationProtocol();
        serializeX11AuthenticationCookie();
        serializeX11ScreenNumber();
    }
}
