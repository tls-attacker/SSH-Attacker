/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.NewCompressMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class NewCompressMessagePreparator extends SshMessagePreparator<NewCompressMessage> {

    public NewCompressMessagePreparator() {
        super(MessageIdConstant.SSH_MSG_NEWCOMPRESS);
    }

    @Override
    public void prepareMessageSpecificContents(NewCompressMessage object, Chooser chooser) {}
}
