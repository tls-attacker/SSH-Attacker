/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.handler;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessageHandler;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.VersionExchangeMessageSSHV1;

public class VersionExchangeMessageSSHV1Handler
        extends ProtocolMessageHandler<VersionExchangeMessageSSHV1> {

    public VersionExchangeMessageSSHV1Handler(SshContext context) {
        super(context);
    }

    /*public VersionExchangeMessageHandler(SshContext context, VersionExchangeMessage message) {
        super(context, message);
    }*/

    @Override
    public void adjustContext(VersionExchangeMessageSSHV1 message) {
        if (sshContext.isHandleAsClient()) {
            sshContext.setServerVersion(message.getVersion().getValue());
            sshContext.setServerComment(message.getComment().getValue());
            // sshContext.getExchangeHashInputHolder().setServerVersion(message);
        } else {
            sshContext.setClientVersion(message.getVersion().getValue());
            sshContext.setClientComment(message.getComment().getValue());
            // sshContext.getExchangeHashInputHolder().setClientVersion(message);
        }
    }

    /*@Override
    public VersionExchangeMessageParser getParser(byte[] array) {
        return new VersionExchangeMessageParser(array);
    }

    @Override
    public VersionExchangeMessageParser getParser(byte[] array, int startPosition) {
        return new VersionExchangeMessageParser(array, startPosition);
    }

    @Override
    public VersionExchangeMessagePreparator getPreparator() {
        return new VersionExchangeMessagePreparator(context.getChooser(), message);
    }

    @Override
    public VersionExchangeMessageSerializer getSerializer() {
        return new VersionExchangeMessageSerializer(message);
    }*/
}
