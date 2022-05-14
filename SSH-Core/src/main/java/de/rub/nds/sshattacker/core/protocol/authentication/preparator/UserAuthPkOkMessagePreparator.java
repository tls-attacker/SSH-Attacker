package de.rub.nds.sshattacker.core.protocol.authentication.preparator;

import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthPkOkMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class UserAuthPkOkMessagePreparator extends SshMessagePreparator<UserAuthPkOkMessage> {

    public UserAuthPkOkMessagePreparator(Chooser chooser, UserAuthPkOkMessage message) {
        super(chooser, message);
    }

    @Override
    public void prepareMessageSpecificContents() { }
}
