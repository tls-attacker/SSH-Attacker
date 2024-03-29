/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIdConstantSSH1;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.AuthPasswordSSH1;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class AuthPasswordPreparator extends SshMessagePreparator<AuthPasswordSSH1> {

    public AuthPasswordPreparator(Chooser chooser, AuthPasswordSSH1 message) {
        super(chooser, message, MessageIdConstantSSH1.SSH_CMSG_AUTH_PASSWORD);
    }

    @Override
    public void prepareMessageSpecificContents() {
        getObject().setPassword(chooser.getConfig().getPassword());
    }
}
