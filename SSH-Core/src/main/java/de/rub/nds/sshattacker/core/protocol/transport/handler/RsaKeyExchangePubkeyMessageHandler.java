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
import de.rub.nds.sshattacker.core.protocol.transport.message.RsaKeyExchangePubkeyMessage;
import de.rub.nds.sshattacker.core.protocol.util.KeyExchangeUtil;

public class RsaKeyExchangePubkeyMessageHandler
        extends SshMessageHandler<RsaKeyExchangePubkeyMessage> {

    public RsaKeyExchangePubkeyMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void adjustContext(RsaKeyExchangePubkeyMessage message) {
        KeyExchangeUtil.handleHostKeyMessage(sshContext, message);
        updateContextWithTransientPublicKey(message);
    }

    private void updateContextWithTransientPublicKey(RsaKeyExchangePubkeyMessage message) {
        sshContext
                .getChooser()
                .getRsaKeyExchange()
                .setTransientKey(message.getTransientPublicKey());
        sshContext.getExchangeHashInputHolder().setRsaTransientKey(message.getTransientPublicKey());
    }
}
