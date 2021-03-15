package de.rub.nds.sshattacker.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.protocol.core.message.Serializer;
import de.rub.nds.sshattacker.protocol.handler.ChannelWindowAdjustMessageHandler;
import de.rub.nds.sshattacker.protocol.handler.Handler;
import de.rub.nds.sshattacker.protocol.preparator.ChannelWindowAdjustMessagePreparator;
import de.rub.nds.sshattacker.protocol.preparator.Preparator;
import de.rub.nds.sshattacker.protocol.serializer.ChannelWindowAdjustMessageSerializer;
import de.rub.nds.sshattacker.state.SshContext;

public class ChannelWindowAdjustMessage extends Message {

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
    public Handler getHandler(SshContext context) {
        return new ChannelWindowAdjustMessageHandler(context);
    }

    @Override
    public Serializer getSerializer() {
        return new ChannelWindowAdjustMessageSerializer(this);
    }

    @Override
    public Preparator getPreparator(SshContext context) {
        return new ChannelWindowAdjustMessagePreparator(context, this);
    }

}
