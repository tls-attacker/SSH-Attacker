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
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelSuccessMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelSuccessMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelSuccessMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelSuccessMessage extends Message<ChannelSuccessMessage> {

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
    public ChannelSuccessMessageHandler getHandler(SshContext context) {
        return new ChannelSuccessMessageHandler(context);
    }

    @Override
    public ChannelSuccessMessageSerializer getSerializer() {
        return new ChannelSuccessMessageSerializer(this);
    }

    @Override
    public ChannelSuccessMessagePreparator getPreparator(SshContext context) {
        return new ChannelSuccessMessagePreparator(context, this);
    }

}
