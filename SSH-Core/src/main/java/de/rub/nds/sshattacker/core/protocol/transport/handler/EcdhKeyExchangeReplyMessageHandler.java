/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.message.EcdhKeyExchangeReplyMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.EcdhKeyExchangeReplyMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.EcdhKeyExchangeReplyMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.EcdhKeyExchangeReplyMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.util.KeyExchangeUtil;
import de.rub.nds.sshattacker.core.state.SshContext;

public class EcdhKeyExchangeReplyMessageHandler
        extends SshMessageHandler<EcdhKeyExchangeReplyMessage> {

    @Override
    public void adjustContext(SshContext context, EcdhKeyExchangeReplyMessage object) {
        KeyExchangeUtil.handleHostKeyMessage(context, object);
        updateContextWithRemotePublicKey(context, object);
        KeyExchangeUtil.computeSharedSecret(context, context.getChooser().getEcdhKeyExchange());
        KeyExchangeUtil.computeExchangeHash(context);
        KeyExchangeUtil.handleExchangeHashSignatureMessage(context, object);
        KeyExchangeUtil.setSessionId(context);
        KeyExchangeUtil.generateKeySet(context);
    }

    private static void updateContextWithRemotePublicKey(
            SshContext context, EcdhKeyExchangeReplyMessage object) {
        context.getChooser()
                .getEcdhKeyExchange()
                .setRemotePublicKey(object.getEphemeralPublicKey().getValue());
        context.getExchangeHashInputHolder()
                .setEcdhServerPublicKey(object.getEphemeralPublicKey().getValue());
    }

    @Override
    public EcdhKeyExchangeReplyMessageParser getParser(byte[] array, SshContext context) {
        return new EcdhKeyExchangeReplyMessageParser(array);
    }

    @Override
    public EcdhKeyExchangeReplyMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new EcdhKeyExchangeReplyMessageParser(array, startPosition);
    }

    public static final EcdhKeyExchangeReplyMessagePreparator PREPARATOR =
            new EcdhKeyExchangeReplyMessagePreparator();

    public static final EcdhKeyExchangeReplyMessageSerializer SERIALIZER =
            new EcdhKeyExchangeReplyMessageSerializer();
}
