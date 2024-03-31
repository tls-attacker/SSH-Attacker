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
import de.rub.nds.sshattacker.core.protocol.ssh1.general.handler.ChannelDataMessageSSHV1Handler;
import de.rub.nds.sshattacker.core.protocol.ssh1.general.parser.ChannelDataMessageSSHV1Parser;
import de.rub.nds.sshattacker.core.protocol.ssh1.general.preparator.ChannelDataMessageSSHV1Preparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.general.serializer.ChannelDataMessageSSHV1Serializier;
import java.io.InputStream;

public class ChannelDataMessageSSH1 extends Ssh1Message<ChannelDataMessageSSH1> {

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
        this.remoteChannel =
                ModifiableVariableFactory.safelySetValue(this.remoteChannel, remoteChannel);
    }

    @Override
    public ChannelDataMessageSSHV1Handler getHandler(SshContext sshContext) {
        return new ChannelDataMessageSSHV1Handler(sshContext);
    }

    @Override
    public Ssh1MessageParser<ChannelDataMessageSSH1> getParser(
            SshContext context, InputStream stream) {
        return new ChannelDataMessageSSHV1Parser(context, stream);
    }

    @Override
    public Ssh1MessagePreparator<ChannelDataMessageSSH1> getPreparator(SshContext sshContext) {
        return new ChannelDataMessageSSHV1Preparator(sshContext.getChooser(), this);
    }

    @Override
    public Ssh1MessageSerializer<ChannelDataMessageSSH1> getSerializer(SshContext sshContext) {
        return new ChannelDataMessageSSHV1Serializier(this);
    }

    @Override
    public String toShortString() {
        return "SSH_MSG_CHANNEL_DATA";
    }
}
