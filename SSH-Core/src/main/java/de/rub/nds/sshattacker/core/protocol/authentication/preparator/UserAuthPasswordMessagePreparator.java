/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.preparator;

import de.rub.nds.sshattacker.core.constants.AuthenticationMethod;
import de.rub.nds.sshattacker.core.constants.ServiceType;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthPasswordMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class UserAuthPasswordMessagePreparator
        extends UserAuthRequestMessagePreparator<UserAuthPasswordMessage> {

    public UserAuthPasswordMessagePreparator(Chooser chooser, UserAuthPasswordMessage message) {
        super(chooser, message, AuthenticationMethod.PASSWORD);
    }

    @Override
    public void prepareUserAuthRequestSpecificContents() {
        getObject().setUserName(chooser.getConfig().getUsername(), true);
        getObject().setServiceName(ServiceType.SSH_CONNECTION, true);
        getObject().setMethodName(AuthenticationMethod.PASSWORD, true);
        getObject().setChangePassword(false);
        getObject().setPassword(chooser.getConfig().getPassword(), true);
        getObject().setNewPassword(chooser.getConfig().getPassword(), true);
    }
}
