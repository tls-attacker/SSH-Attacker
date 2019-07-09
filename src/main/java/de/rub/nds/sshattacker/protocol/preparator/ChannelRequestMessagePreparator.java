package de.rub.nds.sshattacker.protocol.preparator;

import de.rub.nds.sshattacker.protocol.message.ChannelRequestMessage;
import de.rub.nds.sshattacker.state.SshContext;
import de.rub.nds.sshattacker.util.Converter;

public class ChannelRequestMessagePreparator extends Preparator<ChannelRequestMessage> {

    public ChannelRequestMessagePreparator(SshContext context, ChannelRequestMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        message.setReplyWanted(context.getChooser().getReplyWanted());
        message.setRequestType(context.getChooser().getChannelRequestType());
        message.setPayload(Converter.stringToLengthPrefixedString(context.getChooser().getChannelCommand()));
        message.setRecipientChannel(context.getChooser().getRemoteChannel());
    }

}
