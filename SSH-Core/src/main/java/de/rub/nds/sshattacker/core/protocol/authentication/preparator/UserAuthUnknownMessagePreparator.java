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
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthUnknownMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class UserAuthUnknownMessagePreparator extends SshMessagePreparator<UserAuthUnknownMessage> {

    public UserAuthUnknownMessagePreparator(Chooser chooser, UserAuthUnknownMessage message) {
        super(chooser, message);
    }

    @Override
    public void prepareMessageSpecificContents() {
        getObject().setUserName(chooser.getConfig().getUsername(), true);
        getObject().setServiceName(ServiceType.SSH_CONNECTION, true);
        getObject().setMethodName(AuthenticationMethod.PASSWORD, true);
        getObject().setMethodSpecificFields(new byte[0]);
    }
}
