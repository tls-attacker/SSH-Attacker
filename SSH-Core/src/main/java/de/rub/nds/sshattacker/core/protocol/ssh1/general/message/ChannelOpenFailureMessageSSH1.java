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
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1Message;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageParser;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageSerializer;
import de.rub.nds.sshattacker.core.protocol.ssh1.general.handler.ChannelOpenFailureMessageSSHV1Handler;
import de.rub.nds.sshattacker.core.protocol.ssh1.general.parser.ChannelOpenFailureMessageSSHV1Parser;
import de.rub.nds.sshattacker.core.protocol.ssh1.general.preparator.ChannelOpenFailureMessageSSHV1Preparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.general.serializer.ChannelOpenFailureMessageSSHV1Serializier;
import java.io.InputStream;

public class ChannelOpenFailureMessageSSH1 extends Ssh1Message<ChannelOpenFailureMessageSSH1> {

    private ModifiableInteger remoteChannel;

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
    public ChannelOpenFailureMessageSSHV1Handler getHandler(SshContext sshContext) {
        return new ChannelOpenFailureMessageSSHV1Handler(sshContext);
    }

    @Override
    public Ssh1MessageParser<ChannelOpenFailureMessageSSH1> getParser(
            SshContext context, InputStream stream) {
        return new ChannelOpenFailureMessageSSHV1Parser(context, stream);
    }

    @Override
    public Ssh1MessagePreparator<ChannelOpenFailureMessageSSH1> getPreparator(
            SshContext sshContext) {
        return new ChannelOpenFailureMessageSSHV1Preparator(sshContext.getChooser(), this);
    }

    @Override
    public Ssh1MessageSerializer<ChannelOpenFailureMessageSSH1> getSerializer(
            SshContext sshContext) {
        return new ChannelOpenFailureMessageSSHV1Serializier(this);
    }

    @Override
    public String toShortString() {
        return "SSH_MSG_CHANNEL_OPEN_FAILURE";
    }
}
