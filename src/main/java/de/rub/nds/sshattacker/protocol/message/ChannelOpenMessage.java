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
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.protocol.handler.ChannelOpenMessageHandler;
import de.rub.nds.sshattacker.protocol.preparator.ChannelOpenMessagePreparator;
import de.rub.nds.sshattacker.protocol.serializer.ChannelOpenMessageSerializer;
import de.rub.nds.sshattacker.state.SshContext;

public class ChannelOpenMessage extends Message<ChannelOpenMessage> {

    private ModifiableString channelType;
    private ModifiableInteger senderChannel;
    private ModifiableInteger windowSize;
    private ModifiableInteger packetSize;

    public ChannelOpenMessage() {
    }

    public ModifiableString getChannelType() {
        return channelType;
    }

    public void setChannelType(ModifiableString channelType) {
        this.channelType = channelType;
    }

    public void setChannelType(String channelType) {
        this.channelType = ModifiableVariableFactory.safelySetValue(this.channelType, channelType);
    }

    public ModifiableInteger getSenderChannel() {
        return senderChannel;
    }

    public void setSenderChannel(ModifiableInteger senderChannel) {
        this.senderChannel = senderChannel;
    }

    public void setSenderChannel(Integer senderChannel) {
        this.senderChannel = ModifiableVariableFactory.safelySetValue(this.senderChannel, senderChannel);
    }

    public ModifiableInteger getWindowSize() {
        return windowSize;
    }

    public void setWindowSize(ModifiableInteger windowSize) {
        this.windowSize = windowSize;
    }

    public void setWindowSize(Integer windowSize) {
        this.windowSize = ModifiableVariableFactory.safelySetValue(this.windowSize, windowSize);
    }

    public ModifiableInteger getPacketSize() {
        return packetSize;
    }

    public void setPacketSize(ModifiableInteger packetSize) {
        this.packetSize = packetSize;
    }

    public void setPacketSize(Integer packetSize) {
        this.packetSize = ModifiableVariableFactory.safelySetValue(this.packetSize, packetSize);
    }

    @Override
    public String toCompactString() {
        return this.getClass().getSimpleName();
    }

    @Override
    public ChannelOpenMessageHandler getHandler(SshContext context) {
        return new ChannelOpenMessageHandler(context);
    }

    @Override
    public ChannelOpenMessageSerializer getSerializer() {
        return new ChannelOpenMessageSerializer(this);
    }

    @Override
    public ChannelOpenMessagePreparator getPreparator(SshContext context) {
        return new ChannelOpenMessagePreparator(context, this);
    }

}
