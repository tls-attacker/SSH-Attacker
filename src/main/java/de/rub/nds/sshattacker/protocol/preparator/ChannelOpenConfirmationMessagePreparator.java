package de.rub.nds.sshattacker.protocol.preparator;

import de.rub.nds.sshattacker.constants.MessageIDConstant;
import de.rub.nds.sshattacker.protocol.message.ChannelOpenConfirmationMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class ChannelOpenConfirmationMessagePreparator extends Preparator<ChannelOpenConfirmationMessage> {

    public ChannelOpenConfirmationMessagePreparator(SshContext context, ChannelOpenConfirmationMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        message.setMessageID(MessageIDConstant.SSH_MSG_CHANNEL_OPEN_CONFIRMATION.id);
        // TODO dummy values for fuzzing

        message.setPacketSize(Integer.MAX_VALUE);
        message.setRecipientChannel(Integer.MAX_VALUE);
        message.setSenderChannel(Integer.MAX_VALUE);
        message.setWindowSize(Integer.MAX_VALUE);
    }

}
