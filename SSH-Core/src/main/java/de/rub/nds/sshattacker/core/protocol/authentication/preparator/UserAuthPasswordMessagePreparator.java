/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.preparator;

import de.rub.nds.sshattacker.core.constants.AuthenticationMethod;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthPasswordMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class UserAuthPasswordMessagePreparator
        extends UserAuthRequestMessagePreparator<UserAuthPasswordMessage> {

    public UserAuthPasswordMessagePreparator(Chooser chooser, UserAuthPasswordMessage message) {
        super(chooser, message, AuthenticationMethod.PASSWORD);
    }

    @Override
    public void prepareUserAuthRequestSpecificContents() {
        object.setSoftlyChangePassword(false);

        object.setSoftlyPassword(config.getPassword(), true, config);
        object.setSoftlyNewPassword("newPassword", true, config);
    }
}
