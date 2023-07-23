/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.preparator;

import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.VersionExchangeMessageSSHV1;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class VersionExchangeMessageSSHV1Preparator
        extends ProtocolMessagePreparator<VersionExchangeMessageSSHV1> {

    public VersionExchangeMessageSSHV1Preparator(
            Chooser chooser, VersionExchangeMessageSSHV1 message) {
        super(chooser, message);
    }

    @Override
    public void prepareProtocolMessageContents() {
        if (chooser.getContext().getSshContext().isClient()) {
            getObject().setVersion(chooser.getClientVersion());
            getObject().setComment(chooser.getClientComment());
            getObject().setEndOfMessageSequence(chooser.getClientEndOfMessageSequence());
            /*chooser.getContext()
            .getSshContext()
            .getExchangeHashInputHolder()
            .setClientVersion(getObject());*/
        } else {
            getObject().setVersion(chooser.getServerVersion());
            getObject().setComment(chooser.getServerComment());
            getObject().setEndOfMessageSequence(chooser.getServerEndOfMessageSequence());
            /*            chooser.getContext()
            .getSshContext()
            .getExchangeHashInputHolder()
            .setServerVersion(getObject());*/
        }
    }
}
