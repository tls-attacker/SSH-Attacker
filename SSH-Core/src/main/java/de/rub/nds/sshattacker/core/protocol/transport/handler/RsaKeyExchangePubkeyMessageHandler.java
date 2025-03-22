/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.message.RsaKeyExchangePubkeyMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.RsaKeyExchangePubkeyMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.RsaKeyExchangePubkeyMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.RsaKeyExchangePubkeyMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.util.KeyExchangeUtil;
import de.rub.nds.sshattacker.core.state.SshContext;

public class RsaKeyExchangePubkeyMessageHandler
        extends SshMessageHandler<RsaKeyExchangePubkeyMessage> {

    @Override
    public void adjustContext(SshContext context, RsaKeyExchangePubkeyMessage object) {
        KeyExchangeUtil.handleHostKeyMessage(context, object);
        updateContextWithTransientPublicKey(context, object);
    }

    private static void updateContextWithTransientPublicKey(
            SshContext context, RsaKeyExchangePubkeyMessage message) {
        context.getChooser()
                .getRsaKeyExchange()
                .setPublicKey(message.getTransientPublicKey().getPublicKey());
        context.getExchangeHashInputHolder().setRsaTransientKey(message.getTransientPublicKey());
    }

    @Override
    public RsaKeyExchangePubkeyMessageParser getParser(byte[] array, SshContext context) {
        return new RsaKeyExchangePubkeyMessageParser(array);
    }

    @Override
    public RsaKeyExchangePubkeyMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new RsaKeyExchangePubkeyMessageParser(array, startPosition);
    }

    public static final RsaKeyExchangePubkeyMessagePreparator PREPARATOR =
            new RsaKeyExchangePubkeyMessagePreparator();

    public static final RsaKeyExchangePubkeyMessageSerializer SERIALIZER =
            new RsaKeyExchangePubkeyMessageSerializer();
}
