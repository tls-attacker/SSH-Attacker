/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthFailureMessage;
import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.state.SshContext;

public class UserAuthFailureMessagePreparator extends Preparator<UserAuthFailureMessage> {

    public UserAuthFailureMessagePreparator(SshContext context, UserAuthFailureMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        getObject().setMessageID(MessageIDConstant.SSH_MSG_USERAUTH_FAILURE);

        // TODO dummy values for fuzzing
        getObject().setPossibleAuthenticationMethods("", true);
        getObject().setPartialSuccess(true);
    }
}
