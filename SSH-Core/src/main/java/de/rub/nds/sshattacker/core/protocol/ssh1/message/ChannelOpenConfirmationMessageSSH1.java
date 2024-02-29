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
import de.rub.nds.sshattacker.core.protocol.ssh1.handler.ChannelOpenConfirmationMessageSSHV1Handler;
import de.rub.nds.sshattacker.core.protocol.ssh1.parser.ChannelOpenConfirmationMessageSSHV1Parser;
import de.rub.nds.sshattacker.core.protocol.ssh1.preparator.ChannelOpenConfirmationMessageSSHV1Preparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.preparator.ExitStatusMessageSSHV1Preparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.serializer.ChannelOpenConfirmationMessageSSHV1Serializier;
import de.rub.nds.sshattacker.core.protocol.ssh1.serializer.ExitStatusMessageSSHV1Serializier;

import java.io.InputStream;

public class ChannelOpenConfirmationMessageSSH1 extends SshMessage<ChannelOpenConfirmationMessageSSH1> {

    private ModifiableInteger localChannel;
    private ModifiableInteger remoteChannel;

    public ModifiableInteger getLocalChannel() {
        return localChannel;
    }

    public void setLocalChannel(ModifiableInteger localChannel) {
        this.localChannel = localChannel;
    }

    public void setLocalChannel(int localChannel) {
        this.localChannel = ModifiableVariableFactory.safelySetValue(this.localChannel, localChannel);
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
    public ChannelOpenConfirmationMessageSSHV1Handler getHandler(SshContext context) {
        return new ChannelOpenConfirmationMessageSSHV1Handler(context);
    }

    @Override
    public SshMessageParser<ChannelOpenConfirmationMessageSSH1> getParser(
            SshContext context, InputStream stream) {
        return new ChannelOpenConfirmationMessageSSHV1Parser(context, stream);
    }

    @Override
    public SshMessagePreparator<ChannelOpenConfirmationMessageSSH1> getPreparator(SshContext context) {
        return new ChannelOpenConfirmationMessageSSHV1Preparator(context.getChooser(), this);
    }

    @Override
    public SshMessageSerializer<ChannelOpenConfirmationMessageSSH1> getSerializer(SshContext context) {
        return new ChannelOpenConfirmationMessageSSHV1Serializier(this);
    }

    @Override
    public String toShortString() {
        return "SSH_MSG_CHANNEL_OPEN_CONFIRMATION";
    }
}
