/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeOldRequestMessage;

public class DhGexKeyExchangeOldRequestMessageHandler
        extends SshMessageHandler<DhGexKeyExchangeOldRequestMessage> {

    public DhGexKeyExchangeOldRequestMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void adjustContext(DhGexKeyExchangeOldRequestMessage message) {
        updateContextWithPreferredGroupSize(message);
        sshContext.setOldGroupRequestReceived(true);
    }

    private void updateContextWithPreferredGroupSize(DhGexKeyExchangeOldRequestMessage message) {
        sshContext.setPreferredDhGroupSize(message.getPreferredGroupSize().getValue());
        sshContext
                .getExchangeHashInputHolder()
                .setDhGexPreferredGroupSize(message.getPreferredGroupSize().getValue());
    }
}
