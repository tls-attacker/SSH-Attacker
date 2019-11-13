package de.rub.nds.sshattacker.protocol.preparator;

import de.rub.nds.sshattacker.constants.MessageIDConstant;
import de.rub.nds.sshattacker.protocol.message.ChannelWindowAdjustMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class ChannelWindowAdjustMessagePreparator extends Preparator<ChannelWindowAdjustMessage> {

    public ChannelWindowAdjustMessagePreparator(SshContext context, ChannelWindowAdjustMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        message.setMessageID(MessageIDConstant.SSH_MSG_CHANNEL_WINDOW_ADJUST.id);

        // TODO dummy values for fuzzing
        message.setRecipientChannel(Integer.MAX_VALUE);
        message.setBytesToAdd(Integer.MAX_VALUE);
    }

}
