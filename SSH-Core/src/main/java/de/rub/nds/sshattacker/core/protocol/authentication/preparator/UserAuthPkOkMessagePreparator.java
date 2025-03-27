/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthPkOkMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class UserAuthPkOkMessagePreparator extends SshMessagePreparator<UserAuthPkOkMessage> {

    public UserAuthPkOkMessagePreparator(Chooser chooser, UserAuthPkOkMessage message) {
        super(chooser, message, MessageIdConstant.SSH_MSG_USERAUTH_PK_OK);
    }

    @Override
    public void prepareMessageSpecificContents() {
        // TODO: Replace dummy values with values from request or default ones from the chooser
        getObject().setPublicKeyAlgorithmName("", true);
        getObject().setPublicKeyBlob(new byte[0], true);
    }
}
