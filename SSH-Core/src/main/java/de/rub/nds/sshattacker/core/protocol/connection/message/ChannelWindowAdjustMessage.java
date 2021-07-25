/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.protocol.common.Message;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelWindowAdjustMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelWindowAdjustMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelWindowAdjustMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelWindowAdjustMessage extends Message<ChannelWindowAdjustMessage> {

    private ModifiableInteger recipientChannel;
    private ModifiableInteger bytesToAdd;

    public ModifiableInteger getRecipientChannel() {
        return recipientChannel;
    }

    public void setRecipientChannel(ModifiableInteger recipientChannel) {
        this.recipientChannel = recipientChannel;
    }

    public void setRecipientChannel(int recipientChannel) {
        this.recipientChannel = ModifiableVariableFactory.safelySetValue(this.recipientChannel, recipientChannel);
    }

    public ModifiableInteger getBytesToAdd() {
        return bytesToAdd;
    }

    public void setBytesToAdd(ModifiableInteger bytesToAdd) {
        this.bytesToAdd = bytesToAdd;
    }

    public void setBytesToAdd(int bytesToAdd) {
        this.bytesToAdd = ModifiableVariableFactory.safelySetValue(this.bytesToAdd, bytesToAdd);
    }

    @Override
    public ChannelWindowAdjustMessageHandler getHandler(SshContext context) {
        return new ChannelWindowAdjustMessageHandler(context);
    }

    @Override
    public ChannelWindowAdjustMessageSerializer getSerializer() {
        return new ChannelWindowAdjustMessageSerializer(this);
    }

    @Override
    public ChannelWindowAdjustMessagePreparator getPreparator(SshContext context) {
        return new ChannelWindowAdjustMessagePreparator(context, this);
    }

}
