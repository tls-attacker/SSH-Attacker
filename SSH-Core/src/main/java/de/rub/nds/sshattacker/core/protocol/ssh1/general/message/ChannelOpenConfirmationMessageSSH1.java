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
import de.rub.nds.sshattacker.core.protocol.ssh1.general.handler.ChannelOpenConfirmationMessageSSHV1Handler;
import de.rub.nds.sshattacker.core.protocol.ssh1.general.parser.ChannelOpenConfirmationMessageSSHV1Parser;
import de.rub.nds.sshattacker.core.protocol.ssh1.general.preparator.ChannelOpenConfirmationMessageSSHV1Preparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.general.serializer.ChannelOpenConfirmationMessageSSHV1Serializier;
import java.io.InputStream;

public class ChannelOpenConfirmationMessageSSH1
        extends Ssh1Message<ChannelOpenConfirmationMessageSSH1> {

    private ModifiableInteger localChannel;
    private ModifiableInteger remoteChannel;

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
    public ChannelOpenConfirmationMessageSSHV1Handler getHandler(SshContext sshContext) {
        return new ChannelOpenConfirmationMessageSSHV1Handler(sshContext);
    }

    @Override
    public Ssh1MessageParser<ChannelOpenConfirmationMessageSSH1> getParser(
            SshContext context, InputStream stream) {
        return new ChannelOpenConfirmationMessageSSHV1Parser(context, stream);
    }

    @Override
    public Ssh1MessagePreparator<ChannelOpenConfirmationMessageSSH1> getPreparator(
            SshContext sshContext) {
        return new ChannelOpenConfirmationMessageSSHV1Preparator(sshContext.getChooser(), this);
    }

    @Override
    public Ssh1MessageSerializer<ChannelOpenConfirmationMessageSSH1> getSerializer(
            SshContext sshContext) {
        return new ChannelOpenConfirmationMessageSSHV1Serializier(this);
    }

    @Override
    public String toShortString() {
        return "SSH_MSG_CHANNEL_OPEN_CONFIRMATION";
    }
}
