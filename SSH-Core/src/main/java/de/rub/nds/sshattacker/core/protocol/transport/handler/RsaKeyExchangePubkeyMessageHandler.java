/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.RsaKeyExchangePubkeyMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.RsaKeyExchangePubkeyMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.RsaKeyExchangePubkeyMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.RsaKeyExchangePubkeyMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.util.KeyExchangeUtil;
import de.rub.nds.sshattacker.core.state.SshContext;

public class RsaKeyExchangePubkeyMessageHandler
        extends SshMessageHandler<RsaKeyExchangePubkeyMessage> {

    public RsaKeyExchangePubkeyMessageHandler(SshContext context) {
        super(context);
    }

    public RsaKeyExchangePubkeyMessageHandler(
            SshContext context, RsaKeyExchangePubkeyMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        KeyExchangeUtil.handleHostKeyMessage(context, message);
        updateContextWithTransientPublicKey(message);
    }

    private void updateContextWithTransientPublicKey(RsaKeyExchangePubkeyMessage message) {
        context.getChooser().getRsaKeyExchange().setTransientKey(message.getTransientPublicKey());
        context.getExchangeHashInputHolder().setRsaTransientKey(message.getTransientPublicKey());
    }

    @Override
    public SshMessageParser<RsaKeyExchangePubkeyMessage> getParser(byte[] array) {
        return new RsaKeyExchangePubkeyMessageParser(array);
    }

    @Override
    public SshMessageParser<RsaKeyExchangePubkeyMessage> getParser(
            byte[] array, int startPosition) {
        return new RsaKeyExchangePubkeyMessageParser(array, startPosition);
    }

    @Override
    public SshMessagePreparator<RsaKeyExchangePubkeyMessage> getPreparator() {
        return new RsaKeyExchangePubkeyMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SshMessageSerializer<RsaKeyExchangePubkeyMessage> getSerializer() {
        // TODO: Implement Serializer
        return new RsaKeyExchangePubkeyMessageSerializer(message);
    }
}
