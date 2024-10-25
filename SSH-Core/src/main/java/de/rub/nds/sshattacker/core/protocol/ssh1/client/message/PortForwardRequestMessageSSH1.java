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
import de.rub.nds.sshattacker.core.protocol.ssh1.client.handler.PortForwardRequestMessageSSHV1Handler;
import de.rub.nds.sshattacker.core.protocol.ssh1.client.parser.PortForwardRequestMessageSSHV1Parser;
import de.rub.nds.sshattacker.core.protocol.ssh1.client.preparator.PortForwardRequestMessageSSHV1Preparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.client.serializer.PortForwardRequestMessageSSHV1Serializier;
import java.io.InputStream;

public class PortForwardRequestMessageSSH1 extends Ssh1Message<PortForwardRequestMessageSSH1> {

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
        this.portToConnect =
                ModifiableVariableFactory.safelySetValue(this.portToConnect, portToConnect);
    }

    public void setHostToConnect(ModifiableString hostToConnect) {
        this.hostToConnect = hostToConnect;
    }

    public void setHostToConnect(String hostToConnect) {
        this.hostToConnect =
                ModifiableVariableFactory.safelySetValue(this.hostToConnect, hostToConnect);
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
    public PortForwardRequestMessageSSHV1Handler getHandler(SshContext sshContext) {
        return new PortForwardRequestMessageSSHV1Handler(sshContext);
    }

    @Override
    public Ssh1MessageParser<PortForwardRequestMessageSSH1> getParser(
            SshContext context, InputStream stream) {
        return new PortForwardRequestMessageSSHV1Parser(context, stream);
    }

    @Override
    public Ssh1MessagePreparator<PortForwardRequestMessageSSH1> getPreparator(
            SshContext sshContext) {
        return new PortForwardRequestMessageSSHV1Preparator(sshContext.getChooser(), this);
    }

    @Override
    public Ssh1MessageSerializer<PortForwardRequestMessageSSH1> getSerializer(
            SshContext sshContext) {
        return new PortForwardRequestMessageSSHV1Serializier(this);
    }

    @Override
    public String toShortString() {
        return "SSH_CMSG_PORT_FORWARD_REQUEST";
    }
}
