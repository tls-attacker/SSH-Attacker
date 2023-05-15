/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthBannerMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class UserAuthBannerMessagePreparator extends SshMessagePreparator<UserAuthBannerMessage> {

    public UserAuthBannerMessagePreparator(Chooser chooser, UserAuthBannerMessage message) {
        super(chooser, message, MessageIdConstant.SSH_MSG_USERAUTH_BANNER);
    }

    @Override
    public void prepareMessageSpecificContents() {
        // TODO dummy values for fuzzing
        getObject().setMessage("", true);
        getObject().setLanguageTag("", true);
    }
}
