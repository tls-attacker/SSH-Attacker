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
import de.rub.nds.sshattacker.core.protocol.ssh1.handler.PortOpenMessageSSHV1Handler;
import de.rub.nds.sshattacker.core.protocol.ssh1.parser.PortForwardRequestMessageSSHV1Parser;
import de.rub.nds.sshattacker.core.protocol.ssh1.parser.PortOpenMessageSSHV1Parser;
import de.rub.nds.sshattacker.core.protocol.ssh1.preparator.PortForwardRequestMessageSSHV1Preparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.preparator.PortOpenMessageSSHV1Preparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.serializer.PortForwardRequestMessageSSHV1Serializier;
import de.rub.nds.sshattacker.core.protocol.ssh1.serializer.PortOpenMessageSSHV1Serializier;

import java.io.InputStream;

public class PortOpenMessageSSH1 extends SshMessage<PortOpenMessageSSH1> {

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
        this.originatorString = ModifiableVariableFactory.safelySetValue(this.originatorString, originatorString);
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
        this.port = ModifiableVariableFactory.safelySetValue(this.port,port);
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
        this.localChannel = ModifiableVariableFactory.safelySetValue(this.localChannel, localChannel);
    }

    @Override
    public PortOpenMessageSSHV1Handler getHandler(SshContext context) {
        return new PortOpenMessageSSHV1Handler(context);
    }

    @Override
    public SshMessageParser<PortOpenMessageSSH1> getParser(
            SshContext context, InputStream stream) {
        return new PortOpenMessageSSHV1Parser(context, stream);
    }

    @Override
    public SshMessagePreparator<PortOpenMessageSSH1> getPreparator(SshContext context) {
        return new PortOpenMessageSSHV1Preparator(context.getChooser(), this);
    }

    @Override
    public SshMessageSerializer<PortOpenMessageSSH1> getSerializer(SshContext context) {
        return new PortOpenMessageSSHV1Serializier(this);
    }

    @Override
    public String toShortString() {
        return "SSH_MSG_CHANNEL_OPEN_FAILURE";
    }
}
