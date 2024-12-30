/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestX11Message;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelRequestX11MessageSerializer
        extends ChannelRequestMessageSerializer<ChannelRequestX11Message> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeSingleConnection(
            ChannelRequestX11Message object, SerializerStream output) {
        LOGGER.debug("Single connection: {}", object.getSingleConnection().getValue());
        output.appendByte(object.getSingleConnection().getValue());
    }

    private static void serializeX11AuthenticationProtocol(
            ChannelRequestX11Message object, SerializerStream output) {
        Integer x11AuthenticationProtocolLength =
                object.getX11AuthenticationProtocolLength().getValue();
        LOGGER.debug("X11 authentication protocol length: {}", x11AuthenticationProtocolLength);
        output.appendInt(x11AuthenticationProtocolLength);
        LOGGER.debug(
                "X11 authentication protocol: {}",
                object.getX11AuthenticationProtocol().getValue());
        output.appendString(
                object.getX11AuthenticationProtocol().getValue(), StandardCharsets.UTF_8);
    }

    private static void serializeX11AuthenticationCookie(
            ChannelRequestX11Message object, SerializerStream output) {
        Integer x11AuthenticationCookieLength =
                object.getX11AuthenticationCookieLength().getValue();
        LOGGER.debug("X11 authenticaton cookie length: {}", x11AuthenticationCookieLength);
        output.appendInt(x11AuthenticationCookieLength);
        LOGGER.debug(
                "X11 authentication cookie: {}", object.getX11AuthenticationCookie().getValue());
        output.appendString(object.getX11AuthenticationCookie().getValue(), StandardCharsets.UTF_8);
    }

    private static void serializeX11ScreenNumber(
            ChannelRequestX11Message object, SerializerStream output) {
        Integer x11ScreenNumber = object.getX11ScreenNumber().getValue();
        LOGGER.debug("X11 screen number: {}", x11ScreenNumber);
        output.appendInt(x11ScreenNumber);
    }

    @Override
    protected void serializeMessageSpecificContents(
            ChannelRequestX11Message object, SerializerStream output) {
        super.serializeMessageSpecificContents(object, output);
        serializeSingleConnection(object, output);
        serializeX11AuthenticationProtocol(object, output);
        serializeX11AuthenticationCookie(object, output);
        serializeX11ScreenNumber(object, output);
    }
}
