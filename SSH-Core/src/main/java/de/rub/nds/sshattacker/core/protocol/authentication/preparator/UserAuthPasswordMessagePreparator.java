/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.constants.ServiceType;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthPasswordMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class UserAuthPasswordMessagePreparator
        extends SshMessagePreparator<UserAuthPasswordMessage> {

    public UserAuthPasswordMessagePreparator(Chooser chooser, UserAuthPasswordMessage message) {
        super(chooser, message);
    }

    @Override
    public void prepareMessageSpecificContents() {
        getObject().setMessageID(MessageIDConstant.SSH_MSG_USERAUTH_REQUEST);
        getObject().setUserName(chooser.getConfig().getUsername(), true);
        getObject().setServiceName(ServiceType.SSH_CONNECTION, true);
        getObject().setMethodName(chooser.getAuthenticationMethod(), true);
        getObject().setChangePassword(false);
        getObject().setPassword(chooser.getConfig().getPassword(), true);
    }
}
