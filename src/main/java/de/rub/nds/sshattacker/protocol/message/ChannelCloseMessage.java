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
import de.rub.nds.sshattacker.protocol.handler.ChannelCloseMessageHandler;
import de.rub.nds.sshattacker.protocol.handler.Handler;
import de.rub.nds.sshattacker.protocol.preparator.ChannelCloseMessagePreparator;
import de.rub.nds.sshattacker.protocol.preparator.Preparator;
import de.rub.nds.sshattacker.protocol.serializer.ChannelCloseMessageSerializer;
import de.rub.nds.sshattacker.protocol.serializer.Serializer;
import de.rub.nds.sshattacker.state.SshContext;

public class ChannelCloseMessage extends Message<ChannelCloseMessage> {

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
    public Handler<ChannelCloseMessage> getHandler(SshContext context) {
        return new ChannelCloseMessageHandler(context);
    }

    @Override
    public Serializer<ChannelCloseMessage> getSerializer() {
        return new ChannelCloseMessageSerializer(this);
    }

    @Override
    public Preparator<ChannelCloseMessage> getPreparator(SshContext context) {
        return new ChannelCloseMessagePreparator(context, this);
    }

}
