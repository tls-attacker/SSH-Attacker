package de.rub.nds.sshattacker.protocol.preparator;

import de.rub.nds.sshattacker.constants.MessageIDConstant;
import de.rub.nds.sshattacker.protocol.message.GlobalRequestMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class GlobalRequestMessagePreparator extends Preparator<GlobalRequestMessage> {

    public GlobalRequestMessagePreparator(SshContext context, GlobalRequestMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        message.setMessageID(MessageIDConstant.SSH_MSG_GLOBAL_REQUEST.id);

        // TODO dummy values for fuzzing
        message.setWantReply((byte) 0xff);
        message.setRequestName("");
        message.setPayload(new byte[0]);
    }

}
