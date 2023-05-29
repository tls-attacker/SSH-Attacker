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

    /*public EcdhKeyExchangeReplyMessageHandler(
            SshContext context, EcdhKeyExchangeReplyMessage message) {
        super(context, message);
    }*/

    @Override
    public void adjustContext(EcdhKeyExchangeReplyMessage message) {
        KeyExchangeUtil.handleHostKeyMessage(context, message);
        updateContextWithRemotePublicKey(message);
        KeyExchangeUtil.computeSharedSecret(context, context.getChooser().getEcdhKeyExchange());
        KeyExchangeUtil.computeExchangeHash(context);
        KeyExchangeUtil.handleExchangeHashSignatureMessage(context, message);
        KeyExchangeUtil.setSessionId(context);
        KeyExchangeUtil.generateKeySet(context);
    }

    private void updateContextWithRemotePublicKey(EcdhKeyExchangeReplyMessage message) {
        context.getChooser()
                .getEcdhKeyExchange()
                .setRemotePublicKey(message.getEphemeralPublicKey().getValue());
        context.getExchangeHashInputHolder()
                .setEcdhServerPublicKey(message.getEphemeralPublicKey().getValue());
    }

    /*@Override
    public EcdhKeyExchangeReplyMessageParser getParser(byte[] array) {
        return new EcdhKeyExchangeReplyMessageParser(array);
    }

    @Override
    public EcdhKeyExchangeReplyMessageParser getParser(byte[] array, int startPosition) {
        return new EcdhKeyExchangeReplyMessageParser(array, startPosition);
    }

    @Override
    public EcdhKeyExchangeReplyMessagePreparator getPreparator() {
        return new EcdhKeyExchangeReplyMessagePreparator(context.getChooser(), message);
    }

    @Override
    public EcdhKeyExchangeReplyMessageSerializer getSerializer() {
        return new EcdhKeyExchangeReplyMessageSerializer(message);
    }*/
}
