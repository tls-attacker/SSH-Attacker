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
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.ssh1.handler.ChannelCloseMessageSSHV1Handler;
import de.rub.nds.sshattacker.core.protocol.ssh1.handler.ChannelOpenFailureMessageSSHV1Handler;
import de.rub.nds.sshattacker.core.protocol.ssh1.parser.ChannelCloseMessageSSHV1Parser;
import de.rub.nds.sshattacker.core.protocol.ssh1.parser.ChannelOpenFailureMessageSSHV1Parser;
import de.rub.nds.sshattacker.core.protocol.ssh1.preparator.ChannelCloseMessageSSHV1Preparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.preparator.ChannelOpenFailureMessageSSHV1Preparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.serializer.ChannelCloseMessageSSHV1Serializier;
import de.rub.nds.sshattacker.core.protocol.ssh1.serializer.ChannelOpenFailureMessageSSHV1Serializier;

import java.io.InputStream;

public class ChannelCloseMessageSSH1 extends SshMessage<ChannelCloseMessageSSH1> {

    private ModifiableInteger remoteChannel;

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
    public ChannelCloseMessageSSHV1Handler getHandler(SshContext context) {
        return new ChannelCloseMessageSSHV1Handler(context);
    }

    @Override
    public SshMessageParser<ChannelCloseMessageSSH1> getParser(
            SshContext context, InputStream stream) {
        return new ChannelCloseMessageSSHV1Parser(context, stream);
    }

    @Override
    public SshMessagePreparator<ChannelCloseMessageSSH1> getPreparator(SshContext context) {
        return new ChannelCloseMessageSSHV1Preparator(context.getChooser(), this);
    }

    @Override
    public SshMessageSerializer<ChannelCloseMessageSSH1> getSerializer(SshContext context) {
        return new ChannelCloseMessageSSHV1Serializier(this);
    }

    @Override
    public String toShortString() {
        return "SSH_MSG_CHANNEL_OPEN_FAILURE";
    }
}
