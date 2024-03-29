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
import de.rub.nds.sshattacker.core.protocol.transport.message.EcdhKeyExchangeReplyMessage;
import de.rub.nds.sshattacker.core.protocol.util.KeyExchangeUtil;

public class EcdhKeyExchangeReplyMessageHandler
        extends SshMessageHandler<EcdhKeyExchangeReplyMessage> {

    public EcdhKeyExchangeReplyMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void adjustContext(EcdhKeyExchangeReplyMessage message) {
        KeyExchangeUtil.handleHostKeyMessage(sshContext, message);
        updateContextWithRemotePublicKey(message);
        KeyExchangeUtil.computeSharedSecret(
                sshContext, sshContext.getChooser().getEcdhKeyExchange());
        KeyExchangeUtil.computeExchangeHash(sshContext);
        KeyExchangeUtil.handleExchangeHashSignatureMessage(sshContext, message);
        KeyExchangeUtil.setSessionId(sshContext);
        KeyExchangeUtil.generateKeySet(sshContext);
    }

    private void updateContextWithRemotePublicKey(EcdhKeyExchangeReplyMessage message) {
        sshContext
                .getChooser()
                .getEcdhKeyExchange()
                .setRemotePublicKey(message.getEphemeralPublicKey().getValue());
        sshContext
                .getExchangeHashInputHolder()
                .setEcdhServerPublicKey(message.getEphemeralPublicKey().getValue());
    }
}
