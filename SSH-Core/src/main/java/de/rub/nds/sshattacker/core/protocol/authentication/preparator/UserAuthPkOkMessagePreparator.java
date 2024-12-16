/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.crypto.util.PublicKeyHelper;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthPkOkMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class UserAuthPkOkMessagePreparator extends SshMessagePreparator<UserAuthPkOkMessage> {

    public UserAuthPkOkMessagePreparator(Chooser chooser, UserAuthPkOkMessage message) {
        super(chooser, message, MessageIdConstant.SSH_MSG_USERAUTH_PK_OK);
    }

    @Override
    public void prepareMessageSpecificContents() {
        SshPublicKey<?, ?> pk = chooser.getSelectedPublicKeyForAuthentication();
        if (pk != null) {
            getObject().setPubkeyAlgName(pk.getPublicKeyFormat().getName(), true);
            getObject().setPubkey(PublicKeyHelper.encode(pk), true);
        } else {
            getObject().setPubkeyAlgName("", true);
            getObject().setPubkey(new byte[0], true);
        }
    }
}
