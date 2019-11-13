package de.rub.nds.sshattacker.protocol.preparator;

import de.rub.nds.sshattacker.constants.MessageIDConstant;
import de.rub.nds.sshattacker.protocol.message.UnimplementedMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class UnimplementedMessagePreparator extends Preparator<UnimplementedMessage> {

    public UnimplementedMessagePreparator(SshContext context, UnimplementedMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        message.setMessageID(MessageIDConstant.SSH_MSG_UNIMPLEMENTED.id);
    }

}
