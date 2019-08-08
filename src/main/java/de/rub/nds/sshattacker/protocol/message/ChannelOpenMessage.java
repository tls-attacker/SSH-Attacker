package de.rub.nds.sshattacker.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.protocol.core.message.Serializer;
import de.rub.nds.sshattacker.constants.MessageIDConstant;
import de.rub.nds.sshattacker.protocol.handler.Handler;
import de.rub.nds.sshattacker.protocol.serializer.ChannelOpenMessageSerializer;
import de.rub.nds.sshattacker.state.SshContext;

public class ChannelOpenMessage extends Message {

    private ModifiableString channelType;
    private ModifiableInteger senderChannel;
    private ModifiableInteger windowSize;
    private ModifiableInteger packetSize;

    public ChannelOpenMessage(){
        messageID = ModifiableVariableFactory.safelySetValue(messageID, MessageIDConstant.SSH_MSG_CHANNEL_OPEN.id);
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
    public Handler getHandler(SshContext context) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public Serializer getSerializer() {
        return new ChannelOpenMessageSerializer(this);
    }

}
