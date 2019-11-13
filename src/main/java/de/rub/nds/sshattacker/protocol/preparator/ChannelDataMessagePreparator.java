package de.rub.nds.sshattacker.protocol.preparator;

import de.rub.nds.sshattacker.constants.MessageIDConstant;
import de.rub.nds.sshattacker.protocol.message.ChannelDataMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class ChannelDataMessagePreparator extends Preparator<ChannelDataMessage> {

    public ChannelDataMessagePreparator(SshContext context, ChannelDataMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        message.setMessageID(MessageIDConstant.SSH_MSG_CHANNEL_DATA.id);
    }

}
