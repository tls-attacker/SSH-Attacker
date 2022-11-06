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
import de.rub.nds.sshattacker.core.protocol.transport.message.Sntrup761X25519KeyExchangeReplyMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.Sntrup761X25519KeyExchangeReplyMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.Sntrup761X25519KeyExchangeReplyMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.Sntrup761X25519KeyExchangeReplyMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.util.KeyExchangeUtil;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.nio.ByteBuffer;

public class Sntrup761X25519KeyExchangeReplyMessageHandler
        extends SshMessageHandler<Sntrup761X25519KeyExchangeReplyMessage> {

    public Sntrup761X25519KeyExchangeReplyMessageHandler(SshContext context) {
        super(context);
    }

    public Sntrup761X25519KeyExchangeReplyMessageHandler(
            SshContext context, Sntrup761X25519KeyExchangeReplyMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        KeyExchangeUtil.handleHostKeyMessage(context, message);
        setRemoteValues(message.getMultiPrecisionInteger().getValue());
        context.getChooser().getSntrup761X25591KeyExchange().combineSharedSecrets();
        context.setSharedSecret(
                context.getChooser().getSntrup761X25591KeyExchange().getSharedSecret());
        context.getExchangeHashInputHolder()
                .setSharedSecret(
                        context.getChooser().getSntrup761X25591KeyExchange().getSharedSecret());
        KeyExchangeUtil.computeExchangeHash(context);
        KeyExchangeUtil.handleExchangeHashSignatureMessage(context, message);
        KeyExchangeUtil.setSessionId(context);
        KeyExchangeUtil.generateKeySet(context);
    }

    private void setRemoteValues(byte[] values) {
        try {
            ByteBuffer buf = ByteBuffer.wrap(values);
            byte[] sntrup = new byte[values.length - 32];
            byte[] ec25519 = new byte[32];
            buf.get(sntrup, 0, sntrup.length);
            buf.get(ec25519, 0, ec25519.length);

            context.getChooser()
                    .getSntrup761X25591KeyExchange()
                    .getKeyAgreement("ec25519")
                    .setRemotePublicKey(ec25519);
            context.getChooser()
                    .getSntrup761X25591KeyExchange()
                    .getKeyEncapsulation("sntrup761")
                    .setEncapsulatedSecret(sntrup);
            context.getExchangeHashInputHolder()
                    .setSntrupX25519ServerPublicKey(message.getMultiPrecisionInteger().getValue());
        } catch (Exception e) {
            LOGGER.warn("Could not parse the remote Values: " + e);
        }
    }

    @Override
    public SshMessageParser<Sntrup761X25519KeyExchangeReplyMessage> getParser(byte[] array) {
        return new Sntrup761X25519KeyExchangeReplyMessageParser(array);
    }

    @Override
    public SshMessageParser<Sntrup761X25519KeyExchangeReplyMessage> getParser(
            byte[] array, int startPosition) {
        return new Sntrup761X25519KeyExchangeReplyMessageParser(array, startPosition);
    }

    @Override
    public SshMessagePreparator<Sntrup761X25519KeyExchangeReplyMessage> getPreparator() {
        return new Sntrup761X25519KeyExchangeReplyMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SshMessageSerializer<Sntrup761X25519KeyExchangeReplyMessage> getSerializer() {
        return new Sntrup761X25519KeyExchangeReplyMessageSerializer(message);
    }
}
