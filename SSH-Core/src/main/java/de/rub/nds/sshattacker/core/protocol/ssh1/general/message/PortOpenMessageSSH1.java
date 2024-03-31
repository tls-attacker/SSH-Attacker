/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.general.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1Message;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageParser;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageSerializer;
import de.rub.nds.sshattacker.core.protocol.ssh1.general.handler.PortOpenMessageSSHV1Handler;
import de.rub.nds.sshattacker.core.protocol.ssh1.general.parser.PortOpenMessageSSHV1Parser;
import de.rub.nds.sshattacker.core.protocol.ssh1.general.preparator.PortOpenMessageSSHV1Preparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.general.serializer.PortOpenMessageSSHV1Serializier;
import java.io.InputStream;

public class PortOpenMessageSSH1 extends Ssh1Message<PortOpenMessageSSH1> {

    private ModifiableInteger localChannel;
    private ModifiableString hostName;
    private ModifiableInteger port;
    private ModifiableString originatorString;

    public ModifiableString getOriginatorString() {
        return originatorString;
    }

    public void setOriginatorString(ModifiableString originatorString) {
        this.originatorString = originatorString;
    }

    public void setOriginatorString(String originatorString) {
        this.originatorString =
                ModifiableVariableFactory.safelySetValue(this.originatorString, originatorString);
    }

    public ModifiableString getHostName() {
        return hostName;
    }

    public ModifiableInteger getPort() {
        return port;
    }

    public void setPort(ModifiableInteger port) {
        this.port = port;
    }

    public void setPort(int port) {
        this.port = ModifiableVariableFactory.safelySetValue(this.port, port);
    }

    public void setHostName(ModifiableString hostName) {
        this.hostName = hostName;
    }

    public void setHostName(String hostName) {
        this.hostName = ModifiableVariableFactory.safelySetValue(this.hostName, hostName);
    }

    public void getHostName(String hostName) {
        this.hostName = ModifiableVariableFactory.safelySetValue(this.hostName, hostName);
    }

    public ModifiableInteger getLocalChannel() {
        return localChannel;
    }

    public void setLocalChannel(ModifiableInteger localChannel) {
        this.localChannel = localChannel;
    }

    public void setLocalChannel(int localChannel) {
        this.localChannel =
                ModifiableVariableFactory.safelySetValue(this.localChannel, localChannel);
    }

    @Override
    public PortOpenMessageSSHV1Handler getHandler(SshContext sshContext) {
        return new PortOpenMessageSSHV1Handler(sshContext);
    }

    @Override
    public Ssh1MessageParser<PortOpenMessageSSH1> getParser(
            SshContext context, InputStream stream) {
        return new PortOpenMessageSSHV1Parser(context, stream);
    }

    @Override
    public Ssh1MessagePreparator<PortOpenMessageSSH1> getPreparator(SshContext sshContext) {
        return new PortOpenMessageSSHV1Preparator(sshContext.getChooser(), this);
    }

    @Override
    public Ssh1MessageSerializer<PortOpenMessageSSH1> getSerializer(SshContext sshContext) {
        return new PortOpenMessageSSHV1Serializier(this);
    }

    @Override
    public String toShortString() {
        return "SSH_MSG_PORT_OPEN";
    }
}
