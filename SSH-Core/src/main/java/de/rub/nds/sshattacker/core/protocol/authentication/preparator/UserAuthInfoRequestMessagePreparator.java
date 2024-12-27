/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.preparator;

import de.rub.nds.sshattacker.core.config.Config;
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
        Config config = chooser.getConfig();
        object.setSoftlyUserName("", true, config);
        object.setSoftlyInstruction("", true, config);
        object.setSoftlyLanguageTag("", true, config);

        ArrayList<AuthenticationPromptEntry> nextPrompts =
                chooser.getNextPreConfiguredAuthPrompts();

        if (nextPrompts != null) {
            object.setSoftlyPromptEntries(nextPrompts, true, config);
        } else {
            object.setSoftlyPromptEntriesCount(object.getPromptEntries().size(), config);
        }

        object.getPromptEntries().forEach(promptEntry -> promptEntry.prepare(chooser));
    }
}
