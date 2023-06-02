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
import de.rub.nds.sshattacker.core.protocol.transport.message.DhKeyExchangeReplyMessage;
import de.rub.nds.sshattacker.core.protocol.util.KeyExchangeUtil;

public class DhKeyExchangeReplyMessageHandler extends SshMessageHandler<DhKeyExchangeReplyMessage> {

    public DhKeyExchangeReplyMessageHandler(SshContext context) {
        super(context);
    }

    /*public DhKeyExchangeReplyMessageHandler(SshContext context, DhKeyExchangeReplyMessage message) {
        super(context, message);
    }*/

    @Override
    public void adjustContext(DhKeyExchangeReplyMessage message) {
        KeyExchangeUtil.handleHostKeyMessage(sshContext, message);
        updateContextWithRemotePublicKey(message);
        KeyExchangeUtil.computeSharedSecret(sshContext, sshContext.getChooser().getDhKeyExchange());
        KeyExchangeUtil.computeExchangeHash(sshContext);
        KeyExchangeUtil.handleExchangeHashSignatureMessage(sshContext, message);
        KeyExchangeUtil.setSessionId(sshContext);
        KeyExchangeUtil.generateKeySet(sshContext);
    }

    private void updateContextWithRemotePublicKey(DhKeyExchangeReplyMessage message) {
        sshContext
                .getChooser()
                .getDhKeyExchange()
                .setRemotePublicKey(message.getEphemeralPublicKey().getValue());
        sshContext
                .getExchangeHashInputHolder()
                .setDhServerPublicKey(message.getEphemeralPublicKey().getValue());
    }

    /*@Override
    public DhKeyExchangeReplyMessageParser getParser(byte[] array) {
        return new DhKeyExchangeReplyMessageParser(array);
    }

    @Override
    public DhKeyExchangeReplyMessageParser getParser(byte[] array, int startPosition) {
        return new DhKeyExchangeReplyMessageParser(array, startPosition);
    }

    @Override
    public SshMessagePreparator<DhKeyExchangeReplyMessage> getPreparator() {
        return new DhKeyExchangeReplyMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SshMessageSerializer<DhKeyExchangeReplyMessage> getSerializer() {
        return new DhKeyExchangeReplyMessageSerializer(message);
    }*/
}
