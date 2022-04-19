/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.constants.ChannelRequestType;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelRequestX11MessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;
import java.nio.charset.StandardCharsets;

public class ChannelRequestX11Message extends ChannelRequestMessage<ChannelRequestX11Message> {

    private ModifiableByte singleConnection;
    private ModifiableInteger x11AuthenticationProtocolLength;
    private ModifiableString x11AuthenticationProtocol;
    private ModifiableInteger x11AuthenticationCookieLength;
    private ModifiableString x11AuthenticationCookie;
    private ModifiableInteger x11ScreenNumber;

    public ChannelRequestX11Message() {
        super(ChannelRequestType.X11_REQ);
    }

    public ChannelRequestX11Message(Integer senderChannel) {
        super(ChannelRequestType.X11_REQ, senderChannel);
    }

    public ModifiableByte getSingleConnection() {
        return singleConnection;
    }

    public void setSingleConnection(ModifiableByte singleConnection) {
        this.singleConnection = singleConnection;
    }

    public void setSingleConnection(byte singleConnection) {
        this.singleConnection =
                ModifiableVariableFactory.safelySetValue(this.singleConnection, singleConnection);
    }

    public void setSingleConnection(boolean singleConnection) {
        setSingleConnection(Converter.booleanToByte(singleConnection));
    }

    public ModifiableInteger getX11AuthenticationProtocolLength() {
        return x11AuthenticationProtocolLength;
    }

    public void setX11AuthenticationProtocolLength(
            ModifiableInteger x11AuthenticationProtocolLength) {
        this.x11AuthenticationProtocolLength = x11AuthenticationProtocolLength;
    }

    public void setX11AuthenticationProtocolLength(int x11AuthenticationProtocolLength) {
        this.x11AuthenticationProtocolLength =
                ModifiableVariableFactory.safelySetValue(
                        this.x11AuthenticationProtocolLength, x11AuthenticationProtocolLength);
    }

    public ModifiableString getX11AuthenticationProtocol() {
        return x11AuthenticationProtocol;
    }

    public void setX11AuthenticationProtocol(ModifiableString x11AuthenticationProtocol) {
        this.x11AuthenticationProtocol = x11AuthenticationProtocol;
    }

    public void setX11AuthenticationProtocol(String x11AuthenticationProtocol) {
        this.x11AuthenticationProtocol =
                ModifiableVariableFactory.safelySetValue(
                        this.x11AuthenticationProtocol, x11AuthenticationProtocol);
    }

    public void setX11AuthenticationProtocol(
            ModifiableString x11AuthenticationProtocol, boolean adjustLengthField) {
        if (adjustLengthField) {
            setX11AuthenticationProtocolLength(
                    x11AuthenticationProtocol.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
        this.x11AuthenticationProtocol = x11AuthenticationProtocol;
    }

    public void setX11AuthenticationProtocol(
            String x11AuthenticationProtocol, boolean adjustLengthField) {
        if (adjustLengthField) {
            setX11AuthenticationProtocolLength(
                    x11AuthenticationProtocol.getBytes(StandardCharsets.UTF_8).length);
        }
        this.x11AuthenticationProtocol =
                ModifiableVariableFactory.safelySetValue(
                        this.x11AuthenticationProtocol, x11AuthenticationProtocol);
    }

    public ModifiableInteger getX11AuthenticationCookieLength() {
        return x11AuthenticationCookieLength;
    }

    public void setX11AuthenticationCookieLength(ModifiableInteger x11AuthenticationCookieLength) {
        this.x11AuthenticationCookieLength = x11AuthenticationCookieLength;
    }

    public void setX11AuthenticationCookieLength(int x11AuthenticationCookieLength) {
        this.x11AuthenticationCookieLength =
                ModifiableVariableFactory.safelySetValue(
                        this.x11AuthenticationCookieLength, x11AuthenticationCookieLength);
    }

    public ModifiableString getX11AuthenticationCookie() {
        return x11AuthenticationCookie;
    }

    public void setX11AuthenticationCookie(ModifiableString x11AuthenticationCookie) {
        this.x11AuthenticationCookie = x11AuthenticationCookie;
    }

    public void setX11AuthenticationCookie(String x11AuthenticationCookie) {
        this.x11AuthenticationCookie =
                ModifiableVariableFactory.safelySetValue(
                        this.x11AuthenticationCookie, x11AuthenticationCookie);
    }

    public void setX11AuthenticationCookie(
            ModifiableString x11AuthenticationCookie, boolean adjustLengthField) {
        if (adjustLengthField) {
            setX11AuthenticationCookieLength(
                    x11AuthenticationCookie.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
        this.x11AuthenticationCookie = x11AuthenticationCookie;
    }

    public void setX11AuthenticationCookie(
            String x11AuthenticationCookie, boolean adjustLengthField) {
        if (adjustLengthField) {
            setX11AuthenticationCookieLength(
                    x11AuthenticationCookie.getBytes(StandardCharsets.UTF_8).length);
        }
        this.x11AuthenticationCookie =
                ModifiableVariableFactory.safelySetValue(
                        this.x11AuthenticationCookie, x11AuthenticationCookie);
    }

    public ModifiableInteger getX11ScreenNumber() {
        return x11ScreenNumber;
    }

    public void setX11ScreenNumber(ModifiableInteger x11ScreenNumber) {
        this.x11ScreenNumber = x11ScreenNumber;
    }

    public void setX11ScreenNumber(int x11ScreenNumber) {
        this.x11ScreenNumber =
                ModifiableVariableFactory.safelySetValue(this.x11ScreenNumber, x11ScreenNumber);
    }

    @Override
    public ChannelRequestX11MessageHandler getHandler(SshContext context) {
        return new ChannelRequestX11MessageHandler(context, this);
    }
}
