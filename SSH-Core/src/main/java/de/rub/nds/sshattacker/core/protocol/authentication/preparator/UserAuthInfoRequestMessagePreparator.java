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
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class UserAuthInfoRequestMessagePreparator
        extends SshMessagePreparator<UserAuthInfoRequestMessage> {

    public UserAuthInfoRequestMessagePreparator(
            Chooser chooser, UserAuthInfoRequestMessage message) {
        super(chooser, message, MessageIdConstant.SSH_MSG_USERAUTH_INFO_REQUEST);
    }

    @Override
    public void prepareMessageSpecificContents() {
        UserAuthInfoRequestMessage message = object;

        message.setSoftlyUserName("", true, config);
        message.setSoftlyInstruction("", true, config);
        message.setSoftlyLanguageTag("", true, config);
        message.setSoftlyPromptEntriesCount(message.getPromptEntries().size(), config);

        message.getPromptEntries()
                .forEach(
                        promptEntry ->
                                promptEntry
                                        .getHandler(chooser.getContext())
                                        .getPreparator()
                                        .prepare());
    }
}
