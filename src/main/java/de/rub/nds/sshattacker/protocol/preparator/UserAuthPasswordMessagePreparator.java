/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.protocol.preparator;

import de.rub.nds.sshattacker.constants.MessageIDConstant;
import de.rub.nds.sshattacker.protocol.message.UserAuthPasswordMessage;
import de.rub.nds.sshattacker.state.SshContext;

public class UserAuthPasswordMessagePreparator extends Preparator<UserAuthPasswordMessage> {

    public UserAuthPasswordMessagePreparator(SshContext context, UserAuthPasswordMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        message.setMessageID(MessageIDConstant.SSH_MSG_USERAUTH_REQUEST.id);
        message.setUsername(context.getChooser().getUsername());
        message.setPassword(context.getChooser().getPassword());
        message.setServicename("ssh-connection");
        message.setExpectResponse(context.getChooser().getReplyWanted());
    }

}
