/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeReplyMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.DhGexKeyExchangeReplyMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.DhGexKeyExchangeReplyMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.DhGexKeyExchangeReplyMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.util.KeyExchangeUtil;
import de.rub.nds.sshattacker.core.state.SshContext;

public class DhGexKeyExchangeReplyMessageHandler
        extends SshMessageHandler<DhGexKeyExchangeReplyMessage> {

    public DhGexKeyExchangeReplyMessageHandler(SshContext context) {
        super(context);
    }

    public DhGexKeyExchangeReplyMessageHandler(
            SshContext context, DhGexKeyExchangeReplyMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        KeyExchangeUtil.handleHostKeyMessage(context, message);
        updateContextWithRemotePublicKey();
        KeyExchangeUtil.computeSharedSecret(context, context.getChooser().getDhGexKeyExchange());
        KeyExchangeUtil.computeExchangeHash(context);
        KeyExchangeUtil.handleExchangeHashSignatureMessage(context, message);
        KeyExchangeUtil.setSessionId(context);
        KeyExchangeUtil.generateKeySet(context);
    }

    private void updateContextWithRemotePublicKey() {
        context.getChooser()
                .getDhGexKeyExchange()
                .setRemotePublicKey(message.getEphemeralPublicKey().getValue());
        context.getExchangeHashInputHolder()
                .setDhGexServerPublicKey(message.getEphemeralPublicKey().getValue());
    }

    @Override
    public DhGexKeyExchangeReplyMessageParser getParser(byte[] array) {
        return new DhGexKeyExchangeReplyMessageParser(array);
    }

    @Override
    public DhGexKeyExchangeReplyMessageParser getParser(byte[] array, int startPosition) {
        return new DhGexKeyExchangeReplyMessageParser(array, startPosition);
    }

    public static final DhGexKeyExchangeReplyMessagePreparator PREPARATOR =
            new DhGexKeyExchangeReplyMessagePreparator();

    public static final DhGexKeyExchangeReplyMessageSerializer SERIALIZER =
            new DhGexKeyExchangeReplyMessageSerializer();
}
