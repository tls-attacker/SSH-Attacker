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
import de.rub.nds.sshattacker.core.protocol.ssh1.handler.ChannelDataMessageSSHV1Handler;
import de.rub.nds.sshattacker.core.protocol.ssh1.handler.ChannelOpenFailureMessageSSHV1Handler;
import de.rub.nds.sshattacker.core.protocol.ssh1.parser.ChannelDataMessageSSHV1Parser;
import de.rub.nds.sshattacker.core.protocol.ssh1.parser.ChannelOpenFailureMessageSSHV1Parser;
import de.rub.nds.sshattacker.core.protocol.ssh1.preparator.ChannelDataMessageSSHV1Preparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.preparator.ChannelOpenFailureMessageSSHV1Preparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.serializer.ChannelDataMessageSSHV1Serializier;
import de.rub.nds.sshattacker.core.protocol.ssh1.serializer.ChannelOpenFailureMessageSSHV1Serializier;

import java.io.InputStream;

public class ChannelDataMessageSSH1 extends SshMessage<ChannelDataMessageSSH1> {

    private ModifiableInteger remoteChannel;
    private ModifiableString data;

    public ModifiableString getData() {
        return data;
    }

    public void setData(ModifiableString data) {
        this.data = data;
    }

    public void setData(String data) {
        this.data = ModifiableVariableFactory.safelySetValue(this.data, data);
    }


    public ModifiableInteger getRemoteChannel() {
        return remoteChannel;
    }

    public void setRemoteChannel(ModifiableInteger remoteChannel) {
        this.remoteChannel = remoteChannel;
    }

    public void setRemoteChannel(int remoteChannel) {
        this.remoteChannel = ModifiableVariableFactory.safelySetValue(this.remoteChannel, remoteChannel);
    }

    @Override
    public ChannelDataMessageSSHV1Handler getHandler(SshContext context) {
        return new ChannelDataMessageSSHV1Handler(context);
    }

    @Override
    public SshMessageParser<ChannelDataMessageSSH1> getParser(
            SshContext context, InputStream stream) {
        return new ChannelDataMessageSSHV1Parser(context, stream);
    }

    @Override
    public SshMessagePreparator<ChannelDataMessageSSH1> getPreparator(SshContext context) {
        return new ChannelDataMessageSSHV1Preparator(context.getChooser(), this);
    }

    @Override
    public SshMessageSerializer<ChannelDataMessageSSH1> getSerializer(SshContext context) {
        return new ChannelDataMessageSSHV1Serializier(this);
    }

    @Override
    public String toShortString() {
        return "SSH_MSG_CHANNEL_OPEN_FAILURE";
    }
}
