package de.rub.nds.sshattacker.protocol.preparator;

import de.rub.nds.sshattacker.constants.MessageIDConstant;
import de.rub.nds.sshattacker.protocol.message.ChannelFailureMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class ChannelFailureMessagePreparator extends Preparator<ChannelFailureMessage> {

    public ChannelFailureMessagePreparator(SshContext context, ChannelFailureMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        message.setMessageID(MessageIDConstant.SSH_MSG_CHANNEL_FAILURE.id);
    }

}
