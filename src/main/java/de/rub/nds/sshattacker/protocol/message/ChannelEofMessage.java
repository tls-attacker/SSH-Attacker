package de.rub.nds.sshattacker.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.protocol.core.message.Serializer;
import de.rub.nds.sshattacker.protocol.handler.ChannelEofMessageHandler;
import de.rub.nds.sshattacker.protocol.handler.Handler;
import de.rub.nds.sshattacker.protocol.preparator.ChannelEofMessagePreparator;
import de.rub.nds.sshattacker.protocol.preparator.Preparator;
import de.rub.nds.sshattacker.protocol.serializer.ChannelEofMessageSerializer;
import de.rub.nds.sshattacker.state.SshContext;

public class ChannelEofMessage extends Message {

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
    public Handler getHandler(SshContext context) {
        return new ChannelEofMessageHandler(context);
    }

    @Override
    public Serializer getSerializer() {
        return new ChannelEofMessageSerializer(this);
    }

    @Override
    public Preparator getPreparator(SshContext context) {
        return new ChannelEofMessagePreparator(context, this);
    }

}
