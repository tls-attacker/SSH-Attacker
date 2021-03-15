package de.rub.nds.sshattacker.protocol.preparator;

import de.rub.nds.sshattacker.constants.MessageIDConstant;
import de.rub.nds.sshattacker.protocol.message.ChannelOpenFailureMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class ChannelOpenFailureMessagePreparator extends Preparator<ChannelOpenFailureMessage> {

    public ChannelOpenFailureMessagePreparator(SshContext context, ChannelOpenFailureMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        message.setMessageID(MessageIDConstant.SSH_MSG_CHANNEL_FAILURE.id);

        // TODO dummy values for fuzzing
        message.setRecipientChannel(Integer.MAX_VALUE);
        message.setReasonCode(Integer.MAX_VALUE);
        message.setReason("");
        message.setLanguageTag("");
    }

}
