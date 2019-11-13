package de.rub.nds.sshattacker.protocol.preparator;

import de.rub.nds.sshattacker.constants.MessageIDConstant;
import de.rub.nds.sshattacker.protocol.message.ChannelCloseMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class ChannelCloseMessagePreparator extends Preparator<ChannelCloseMessage> {

    public ChannelCloseMessagePreparator(SshContext context, ChannelCloseMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        message.setMessageID(MessageIDConstant.SSH_MSG_CHANNEL_CLOSE.id);
    }

}
