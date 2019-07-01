package de.rub.nds.sshattacker.protocol.preparator;

import de.rub.nds.sshattacker.protocol.message.ChannelOpenMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class ChannelOpenMessagePreparator extends Preparator<ChannelOpenMessage> {

    public ChannelOpenMessagePreparator(SshContext context, ChannelOpenMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        message.setSenderChannel(context.getChooser().getLocalChannel());
        message.setChannelType(context.getChooser().getChannelType());
        message.setWindowSize(context.getChooser().getWindowSize());
        message.setPacketSize(context.getChooser().getPacketSize());
    }

}
