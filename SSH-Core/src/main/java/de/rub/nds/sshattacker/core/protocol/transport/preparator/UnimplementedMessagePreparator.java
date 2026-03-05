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
import de.rub.nds.sshattacker.core.protocol.transport.message.UnimplementedMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class UnimplementedMessagePreparator extends SshMessagePreparator<UnimplementedMessage> {

    public UnimplementedMessagePreparator() {
        super(MessageIdConstant.SSH_MSG_UNIMPLEMENTED);
    }

    @Override
    protected void prepareMessageSpecificContents(UnimplementedMessage object, Chooser chooser) {
        object.setSequenceNumber(Integer.MAX_VALUE);
    }
}
