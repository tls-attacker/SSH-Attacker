package de.rub.nds.sshattacker.protocol.preparator;

import de.rub.nds.sshattacker.constants.MessageIDConstant;
import de.rub.nds.sshattacker.protocol.message.ChannelExtendedDataMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class ChannelExtendedDataMessagePreparator extends Preparator<ChannelExtendedDataMessage> {

    public ChannelExtendedDataMessagePreparator(SshContext context, ChannelExtendedDataMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        message.setMessageID(MessageIDConstant.SSH_MSG_CHANNEL_EXTENDED_DATA.id);
    }

}
