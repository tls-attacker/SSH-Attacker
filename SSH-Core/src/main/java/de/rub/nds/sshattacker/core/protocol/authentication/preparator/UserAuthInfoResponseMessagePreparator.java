/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthInfoResponseMessage;
import de.rub.nds.sshattacker.core.protocol.authentication.message.holder.AuthenticationResponseEntry;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.util.ArrayList;

public class UserAuthInfoResponseMessagePreparator
        extends SshMessagePreparator<UserAuthInfoResponseMessage> {

    public UserAuthInfoResponseMessagePreparator() {
        super(MessageIdConstant.SSH_MSG_USERAUTH_INFO_RESPONSE);
    }

    @Override
    public void prepareMessageSpecificContents(
            UserAuthInfoResponseMessage object, Chooser chooser) {
        ArrayList<AuthenticationResponseEntry> nextResponses =
                chooser.getNextPreConfiguredAuthResponses();

        if (nextResponses != null) {
            object.setResponseEntries(nextResponses, true);
        } else {
            object.setResponseEntriesCount(object.getResponseEntries().size());
        }

        object.getResponseEntries().forEach(responseEntry -> responseEntry.prepare(chooser));
    }
}
