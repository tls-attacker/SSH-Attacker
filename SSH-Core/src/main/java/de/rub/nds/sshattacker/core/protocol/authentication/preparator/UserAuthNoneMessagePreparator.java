/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.preparator;

import de.rub.nds.sshattacker.core.constants.AuthenticationMethod;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthNoneMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class UserAuthNoneMessagePreparator
        extends UserAuthRequestMessagePreparator<UserAuthNoneMessage> {

    public UserAuthNoneMessagePreparator() {
        super(AuthenticationMethod.NONE);
    }

    @Override
    public void prepareUserAuthRequestSpecificContents(
            UserAuthNoneMessage object, Chooser chooser) {}
}
