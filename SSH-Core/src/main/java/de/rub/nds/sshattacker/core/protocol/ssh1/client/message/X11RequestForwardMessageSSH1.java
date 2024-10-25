/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.client.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1Message;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageParser;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageSerializer;
import de.rub.nds.sshattacker.core.protocol.ssh1.client.handler.X11RequestForwardMessageSSHV1Handler;
import de.rub.nds.sshattacker.core.protocol.ssh1.client.parser.X11RequestForwardMessageSSHV1Parser;
import de.rub.nds.sshattacker.core.protocol.ssh1.client.preparator.X11RequestForwardMessageSSHV1Preparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.client.serializer.X11RequestForwardMessageSSHV1Serializier;
import java.io.InputStream;

public class X11RequestForwardMessageSSH1 extends Ssh1Message<X11RequestForwardMessageSSH1> {

    private ModifiableInteger screenNumber;
    private ModifiableString x11AuthenticationProtocol;
    private ModifiableString x11AuthenticationData;

    public ModifiableString getX11AuthenticationData() {
        return x11AuthenticationData;
    }

    public void setX11AuthenticationData(ModifiableString x11AuthenticationData) {
        this.x11AuthenticationData = x11AuthenticationData;
    }

    public void setX11AuthenticationData(String x11AuthenticationData) {
        this.x11AuthenticationData =
                ModifiableVariableFactory.safelySetValue(
                        this.x11AuthenticationData, x11AuthenticationData);
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

    public ModifiableInteger getScreenNumber() {
        return screenNumber;
    }

    public void setScreenNumber(ModifiableInteger screenNumber) {
        this.screenNumber = screenNumber;
    }

    public void setScreenNumber(int screenNumber) {
        this.screenNumber =
                ModifiableVariableFactory.safelySetValue(this.screenNumber, screenNumber);
    }

    @Override
    public X11RequestForwardMessageSSHV1Handler getHandler(SshContext sshContext) {
        return new X11RequestForwardMessageSSHV1Handler(sshContext);
    }

    @Override
    public Ssh1MessageParser<X11RequestForwardMessageSSH1> getParser(
            SshContext context, InputStream stream) {
        return new X11RequestForwardMessageSSHV1Parser(context, stream);
    }

    @Override
    public Ssh1MessagePreparator<X11RequestForwardMessageSSH1> getPreparator(
            SshContext sshContext) {
        return new X11RequestForwardMessageSSHV1Preparator(sshContext.getChooser(), this);
    }

    @Override
    public Ssh1MessageSerializer<X11RequestForwardMessageSSH1> getSerializer(
            SshContext sshContext) {
        return new X11RequestForwardMessageSSHV1Serializier(this);
    }

    @Override
    public String toShortString() {
        return "SSH_CMSG_X11_REQUEST_FORWARDING";
    }
}
