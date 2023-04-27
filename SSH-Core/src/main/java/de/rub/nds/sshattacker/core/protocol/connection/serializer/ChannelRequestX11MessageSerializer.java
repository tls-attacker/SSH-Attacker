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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.charset.StandardCharsets;

public class ChannelRequestX11MessageSerializer
        extends ChannelRequestMessageSerializer<ChannelRequestX11Message> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelRequestX11MessageSerializer(ChannelRequestX11Message message) {
        super(message);
    }

    public void serializeSingleConnection() {
        LOGGER.debug("Single connection: " + message.getSingleConnection().getValue());
        appendByte(message.getSingleConnection().getValue());
    }

    public void serializeX11AuthenticationProtocol() {
        LOGGER.debug(
                "X11 authentication protocol length: "
                        + message.getX11AuthenticationProtocolLength().getValue());
        appendInt(
                message.getX11AuthenticationProtocolLength().getValue(),
                DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "X11 authentication protocol: "
                        + message.getX11AuthenticationProtocol().getValue());
        appendString(message.getX11AuthenticationProtocol().getValue(), StandardCharsets.UTF_8);
    }

    public void serializeX11AuthenticationCookie() {
        LOGGER.debug(
                "X11 authenticaton cookie length: "
                        + message.getX11AuthenticationCookieLength().getValue());
        appendInt(
                message.getX11AuthenticationCookieLength().getValue(),
                DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "X11 authentication cookie: " + message.getX11AuthenticationCookie().getValue());
        appendString(message.getX11AuthenticationCookie().getValue(), StandardCharsets.UTF_8);
    }

    public void serializeX11ScreenNumber() {
        LOGGER.debug("X11 screen number: " + message.getX11ScreenNumber().getValue());
        appendInt(message.getX11ScreenNumber().getValue(), DataFormatConstants.UINT32_SIZE);
    }

    @Override
    public void serializeMessageSpecificContents() {
        super.serializeMessageSpecificContents();
        serializeSingleConnection();
        serializeX11AuthenticationProtocol();
        serializeX11AuthenticationCookie();
        serializeX11ScreenNumber();
    }
}
