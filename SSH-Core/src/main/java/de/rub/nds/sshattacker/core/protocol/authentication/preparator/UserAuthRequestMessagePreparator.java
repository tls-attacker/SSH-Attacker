/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.preparator;

import de.rub.nds.sshattacker.core.constants.AuthenticationMethod;
import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.constants.ServiceType;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthRequestMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public abstract class UserAuthRequestMessagePreparator<T extends UserAuthRequestMessage<T>>
        extends SshMessagePreparator<T> {

    private final AuthenticationMethod authenticationMethod;

    protected UserAuthRequestMessagePreparator(
            Chooser chooser, T message, AuthenticationMethod authenticationMethod) {
        super(chooser, message, MessageIdConstant.SSH_MSG_USERAUTH_REQUEST);
        this.authenticationMethod = authenticationMethod;
    }

    @Override
    public final void prepareMessageSpecificContents() {
        prepareUserAuthRequestSpecificContents();
        object.setSoftlyUserName(config.getUsername(), true, config);
        object.setSoftlyServiceName(ServiceType.SSH_CONNECTION, true, config);
        // Always set correct authentication method -> Don't use soft set
        object.setMethodName(authenticationMethod, true);
    }

    public abstract void prepareUserAuthRequestSpecificContents();
}
