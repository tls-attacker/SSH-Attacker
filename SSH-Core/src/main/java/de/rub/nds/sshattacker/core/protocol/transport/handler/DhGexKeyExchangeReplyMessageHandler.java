/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeReplyMessage;
import de.rub.nds.sshattacker.core.protocol.util.KeyExchangeUtil;

public class DhGexKeyExchangeReplyMessageHandler
        extends SshMessageHandler<DhGexKeyExchangeReplyMessage> {

    public DhGexKeyExchangeReplyMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void adjustContext(DhGexKeyExchangeReplyMessage message) {
        KeyExchangeUtil.handleHostKeyMessage(sshContext, message);
        updateContextWithRemotePublicKey(message);
        KeyExchangeUtil.computeSharedSecret(
                sshContext, sshContext.getChooser().getDhGexKeyExchange());
        KeyExchangeUtil.computeExchangeHash(sshContext);
        KeyExchangeUtil.handleExchangeHashSignatureMessage(sshContext, message);
        KeyExchangeUtil.setSessionId(sshContext);
        KeyExchangeUtil.generateKeySet(sshContext);
    }

    private void updateContextWithRemotePublicKey(DhGexKeyExchangeReplyMessage message) {
        sshContext
                .getChooser()
                .getDhGexKeyExchange()
                .setRemotePublicKey(message.getEphemeralPublicKey().getValue());
        sshContext
                .getExchangeHashInputHolder()
                .setDhGexServerPublicKey(message.getEphemeralPublicKey().getValue());
    }
}
