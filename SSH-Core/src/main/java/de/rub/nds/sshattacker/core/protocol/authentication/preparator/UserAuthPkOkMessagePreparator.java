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

    public UserAuthPkOkMessagePreparator() {
        super(MessageIdConstant.SSH_MSG_USERAUTH_PK_OK);
    }

    @Override
    protected void prepareMessageSpecificContents(UserAuthPkOkMessage object, Chooser chooser) {
        SshPublicKey<?, ?> pk = chooser.getSelectedPublicKeyForAuthentication();

        if (pk != null) {
            object.setPubkeyAlgName(pk.getPublicKeyFormat().getName(), true);
            object.setPubkey(PublicKeyHelper.encode(pk), true);
        } else {
            object.setPubkeyAlgName("", true);
            object.setPubkey(new byte[0], true);
        }
    }
}
