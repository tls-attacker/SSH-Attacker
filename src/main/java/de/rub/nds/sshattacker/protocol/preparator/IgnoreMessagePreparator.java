package de.rub.nds.sshattacker.protocol.preparator;

import de.rub.nds.sshattacker.constants.MessageIDConstant;
import de.rub.nds.sshattacker.protocol.message.IgnoreMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class IgnoreMessagePreparator extends Preparator<IgnoreMessage> {

    public IgnoreMessagePreparator(SshContext context, IgnoreMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        message.setMessageID(MessageIDConstant.SSH_MSG_IGNORE.id);

        // TODO dummy values for fuzzing
        message.setData("");
    }

}
