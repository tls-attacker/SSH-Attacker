/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.ssh1.handler.PortForwardRequestMessageSSHV1Handler;
import de.rub.nds.sshattacker.core.protocol.ssh1.handler.X11OpenMessageSSHV1Handler;
import de.rub.nds.sshattacker.core.protocol.ssh1.parser.PortForwardRequestMessageSSHV1Parser;
import de.rub.nds.sshattacker.core.protocol.ssh1.parser.X11OpenMessageSSHV1Parser;
import de.rub.nds.sshattacker.core.protocol.ssh1.preparator.PortForwardRequestMessageSSHV1Preparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.preparator.X11OpenMessageSSHV1Preparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.serializer.PortForwardRequestMessageSSHV1Serializier;
import de.rub.nds.sshattacker.core.protocol.ssh1.serializer.X11OpenMessageSSHV1Serializier;

import java.io.InputStream;

public class PortForwardRequestMessageSSH1 extends SshMessage<PortForwardRequestMessageSSH1> {

    private ModifiableInteger serverPort;
    private ModifiableString hostToConnect;

    private ModifiableInteger portToConnect;
    public ModifiableString getHostToConnect() {
        return hostToConnect;
    }

    public ModifiableInteger getPortToConnect() {
        return portToConnect;
    }

    public void setPortToConnect(ModifiableInteger portToConnect) {
        this.portToConnect = portToConnect;
    }

    public void setPortToConnect(int portToConnect) {
        this.portToConnect = ModifiableVariableFactory.safelySetValue(this.portToConnect,portToConnect);
    }

    public void setHostToConnect(ModifiableString hostToConnect) {
        this.hostToConnect = hostToConnect;
    }

    public void setHostToConnect(String hostToConnect) {
        this.hostToConnect = ModifiableVariableFactory.safelySetValue(this.hostToConnect, hostToConnect);
    }


    public ModifiableInteger getServerPort() {
        return serverPort;
    }

    public void setServerPort(ModifiableInteger serverPort) {
        this.serverPort = serverPort;
    }

    public void setServerPort(int serverPort) {
        this.serverPort = ModifiableVariableFactory.safelySetValue(this.serverPort, serverPort);
    }

    @Override
    public PortForwardRequestMessageSSHV1Handler getHandler(SshContext context) {
        return new PortForwardRequestMessageSSHV1Handler(context);
    }

    @Override
    public SshMessageParser<PortForwardRequestMessageSSH1> getParser(
            SshContext context, InputStream stream) {
        return new PortForwardRequestMessageSSHV1Parser(context, stream);
    }

    @Override
    public SshMessagePreparator<PortForwardRequestMessageSSH1> getPreparator(SshContext context) {
        return new PortForwardRequestMessageSSHV1Preparator(context.getChooser(), this);
    }

    @Override
    public SshMessageSerializer<PortForwardRequestMessageSSH1> getSerializer(SshContext context) {
        return new PortForwardRequestMessageSSHV1Serializier(this);
    }

    @Override
    public String toShortString() {
        return "SSH_MSG_CHANNEL_OPEN_FAILURE";
    }
}
