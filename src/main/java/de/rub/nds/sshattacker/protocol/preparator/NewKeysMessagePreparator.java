package de.rub.nds.sshattacker.protocol.preparator;

import de.rub.nds.sshattacker.constants.MessageIDConstant;
import de.rub.nds.sshattacker.protocol.message.NewKeysMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class NewKeysMessagePreparator extends Preparator<NewKeysMessage> {

    public NewKeysMessagePreparator(SshContext context, NewKeysMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        message.setMessageID(MessageIDConstant.SSH_MSG_NEWKEYS.id);
    }

}
