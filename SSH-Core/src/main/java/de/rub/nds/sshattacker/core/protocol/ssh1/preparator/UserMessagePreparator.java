/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIdConstantSSH1;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessagePreparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.UserMessageSSH1;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class UserMessagePreparator extends Ssh1MessagePreparator<UserMessageSSH1> {

    public UserMessagePreparator(Chooser chooser, UserMessageSSH1 message) {
        super(chooser, message, MessageIdConstantSSH1.SSH_CMSG_USER);
    }

    @Override
    public void prepareMessageSpecificContents() {
        getObject().setUsername(chooser.getConfig().getUsername());
    }
}
