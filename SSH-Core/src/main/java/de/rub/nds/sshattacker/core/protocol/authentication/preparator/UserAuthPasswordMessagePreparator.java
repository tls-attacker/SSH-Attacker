/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.preparator;

import de.rub.nds.sshattacker.core.constants.AuthenticationMethod;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.constants.ServiceType;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthPasswordMessage;
import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.state.SshContext;

public class UserAuthPasswordMessagePreparator extends Preparator<UserAuthPasswordMessage> {

    public UserAuthPasswordMessagePreparator(SshContext context, UserAuthPasswordMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        message.setMessageID(MessageIDConstant.SSH_MSG_USERAUTH_REQUEST);
        message.setUserName(context.getConfig().getUsername());
        message.setServiceName(ServiceType.SSH_CONNECTION);
        message.setMethodName(AuthenticationMethod.PASSWORD);
        message.setChangePassword(false);
        message.setPassword(context.getConfig().getPassword());
    }

}
