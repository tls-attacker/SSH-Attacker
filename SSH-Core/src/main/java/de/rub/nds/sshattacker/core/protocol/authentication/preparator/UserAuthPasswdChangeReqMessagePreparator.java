/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthPasswdChangeReqMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class UserAuthPasswdChangeReqMessagePreparator
        extends SshMessagePreparator<UserAuthPasswdChangeReqMessage> {

    public UserAuthPasswdChangeReqMessagePreparator(
            Chooser chooser, UserAuthPasswdChangeReqMessage message) {
        super(chooser, message, MessageIdConstant.SSH_MSG_USERAUTH_PASSWD_CHANGEREQ);
    }

    @Override
    public void prepareMessageSpecificContents() {
        // TODO: Replace dummy values
        getObject().setPrompt("Please change your password", true);
        getObject().setLanguageTag("en", true);
    }
}
