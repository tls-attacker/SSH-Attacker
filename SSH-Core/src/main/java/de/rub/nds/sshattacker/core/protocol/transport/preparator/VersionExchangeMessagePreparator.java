/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.VersionExchangeMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class VersionExchangeMessagePreparator
        extends ProtocolMessagePreparator<VersionExchangeMessage> {

    @Override
    protected void prepareProtocolMessageContents(VersionExchangeMessage object, Chooser chooser) {
        if (chooser.getContext().isClient()) {
            object.setVersion(chooser.getClientVersion());
            object.setComment(chooser.getClientComment());
            object.setEndOfMessageSequence(chooser.getClientEndOfMessageSequence());
            chooser.getContext().getExchangeHashInputHolder().setClientVersion(object);
        } else {
            object.setVersion(chooser.getServerVersion());
            object.setComment(chooser.getServerComment());
            object.setEndOfMessageSequence(chooser.getServerEndOfMessageSequence());
            chooser.getContext().getExchangeHashInputHolder().setServerVersion(object);
        }
    }
}
