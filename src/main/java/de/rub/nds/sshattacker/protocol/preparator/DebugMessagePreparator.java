package de.rub.nds.sshattacker.protocol.preparator;

import de.rub.nds.sshattacker.constants.MessageIDConstant;
import de.rub.nds.sshattacker.protocol.message.DebugMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class DebugMessagePreparator extends Preparator<DebugMessage> {

    public DebugMessagePreparator(SshContext context, DebugMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        message.setMessageID(MessageIDConstant.SSH_MSG_DEBUG.id);
    }

}
