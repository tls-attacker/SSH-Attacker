/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.crypto.util.OpenSshHostKeyHelper;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestHostKeysProveSuccessMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class GlobalRequestHostKeysProveSuccessMessagePreparator
        extends ChannelMessagePreparator<GlobalRequestHostKeysProveSuccessMessage> {

    public GlobalRequestHostKeysProveSuccessMessagePreparator(
            Chooser chooser, GlobalRequestHostKeysProveSuccessMessage message) {
        super(chooser, message, MessageIdConstant.SSH_MSG_REQUEST_SUCCESS);
    }

    @Override
    protected void prepareChannelMessageSpecificContents() {
        // ToDo Signature creation of all hostkeys which have set prove bit to 1

        /*string		"hostkeys-prove-00@openssh.com"
        string		session identifier
        string		hostkey*/
        OpenSshHostKeyHelper.createHostKeySignatures(chooser.getContext(), getObject());
    }
}
