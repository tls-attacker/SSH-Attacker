/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.NewKeysMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class NewKeysMessagePreparator extends SshMessagePreparator<NewKeysMessage> {

    public NewKeysMessagePreparator(Chooser chooser, NewKeysMessage message) {
        super(chooser, message, MessageIdConstant.SSH_MSG_NEWKEYS);
    }

    @Override
    public void prepareMessageSpecificContents() {}
}
