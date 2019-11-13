package de.rub.nds.sshattacker.protocol.preparator;

import de.rub.nds.sshattacker.constants.MessageIDConstant;
import de.rub.nds.sshattacker.protocol.message.ChannelSuccessMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class ChannelSuccessMessagePreparator extends Preparator<ChannelSuccessMessage> {

    public ChannelSuccessMessagePreparator(SshContext context, ChannelSuccessMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        message.setMessageID(MessageIDConstant.SSH_MSG_CHANNEL_SUCCESS.id);
    }

}
