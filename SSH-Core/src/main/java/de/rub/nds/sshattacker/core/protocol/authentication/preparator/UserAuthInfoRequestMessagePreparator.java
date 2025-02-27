/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthInfoRequestMessage;
import de.rub.nds.sshattacker.core.protocol.authentication.message.holder.AuthenticationPromptEntry;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.util.ArrayList;

public class UserAuthInfoRequestMessagePreparator
        extends SshMessagePreparator<UserAuthInfoRequestMessage> {

    public UserAuthInfoRequestMessagePreparator() {
        super(MessageIdConstant.SSH_MSG_USERAUTH_INFO_REQUEST);
    }

    @Override
    public void prepareMessageSpecificContents(UserAuthInfoRequestMessage object, Chooser chooser) {
        object.setUserName("", true);
        object.setInstruction("", true);
        object.setLanguageTag("", true);

        ArrayList<AuthenticationPromptEntry> nextPrompts =
                chooser.getNextPreConfiguredAuthPrompts();

        if (nextPrompts != null) {
            object.setPromptEntries(nextPrompts, true);
        } else {
            object.setPromptEntriesCount(object.getPromptEntries().size());
        }

        object.getPromptEntries().forEach(promptEntry -> promptEntry.prepare(chooser));
    }
}
