/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.protocol.handler.ChannelEofMessageHandler;
import de.rub.nds.sshattacker.protocol.preparator.ChannelEofMessagePreparator;
import de.rub.nds.sshattacker.protocol.serializer.ChannelEofMessageSerializer;
import de.rub.nds.sshattacker.state.SshContext;

public class ChannelEofMessage extends Message<ChannelEofMessage> {

    private ModifiableInteger recipientChannel;

    public ModifiableInteger getRecipientChannel() {
        return recipientChannel;
    }

    public void setRecipientChannel(ModifiableInteger recipientChannel) {
        this.recipientChannel = recipientChannel;
    }

    public void setRecipientChannel(int recipientChannel) {
        this.recipientChannel = ModifiableVariableFactory.safelySetValue(this.recipientChannel, recipientChannel);
    }

    @Override
    public ChannelEofMessageHandler getHandler(SshContext context) {
        return new ChannelEofMessageHandler(context);
    }

    @Override
    public ChannelEofMessageSerializer getSerializer() {
        return new ChannelEofMessageSerializer(this);
    }

    @Override
    public ChannelEofMessagePreparator getPreparator(SshContext context) {
        return new ChannelEofMessagePreparator(context, this);
    }

}
