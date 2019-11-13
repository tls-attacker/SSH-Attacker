package de.rub.nds.sshattacker.protocol.preparator;

import de.rub.nds.sshattacker.constants.MessageIDConstant;
import de.rub.nds.sshattacker.protocol.message.ChannelEofMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class ChannelEofMessagePreparator extends Preparator<ChannelEofMessage> {

    public ChannelEofMessagePreparator(SshContext context, ChannelEofMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        message.setMessageID(MessageIDConstant.SSH_MSG_CHANNEL_EOF.id);

        // TODO dummy values for fuzzing
        message.setRecipientChannel(Integer.MAX_VALUE);
    }

}
