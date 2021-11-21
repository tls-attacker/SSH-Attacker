/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.VersionExchangeMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class VersionExchangeMessagePreparator
        extends ProtocolMessagePreparator<VersionExchangeMessage> {

    public VersionExchangeMessagePreparator(Chooser chooser, VersionExchangeMessage message) {
        super(chooser, message);
    }

    @Override
    public void prepareProtocolMessageContents() {
        if (chooser.getContext().isClient()) {
            getObject().setVersion(chooser.getClientVersion());
            getObject().setComment(chooser.getClientComment());
            // TODO: Use chooser here
            getObject().setEndOfMessageSequence(chooser.getEndOfMessageSequence());
            chooser.getContext().getExchangeHashInstance().setClientVersion(getObject());
        } else {
            getObject().setVersion(chooser.getServerVersion());
            getObject().setComment(chooser.getServerComment());
            // TODO: Use chooser here
            getObject().setEndOfMessageSequence(chooser.getEndOfMessageSequence());
            chooser.getContext().getExchangeHashInstance().setServerVersion(getObject());
        }
    }
}
