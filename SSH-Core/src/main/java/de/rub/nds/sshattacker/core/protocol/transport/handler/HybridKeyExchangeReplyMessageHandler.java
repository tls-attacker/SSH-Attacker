/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.crypto.kex.HybridKeyExchange;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.HybridKeyExchangeReplyMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.HybridKeyExchangeReplyMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.HybridKeyExchangeReplyMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.HybridKeyExchangeReplyMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.util.KeyExchangeUtil;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HybridKeyExchangeReplyMessageHandler
        extends SshMessageHandler<HybridKeyExchangeReplyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public HybridKeyExchangeReplyMessageHandler(SshContext context) {
        super(context);
    }

    public HybridKeyExchangeReplyMessageHandler(
            SshContext context, HybridKeyExchangeReplyMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        KeyExchangeUtil.handleHostKeyMessage(context, message);
        splitRemotePublicValues();
        updateContextWithRemotePublicValues();
        KeyExchangeUtil.computeSharedSecret(context, context.getChooser().getHybridKeyExchange());
        KeyExchangeUtil.computeExchangeHash(context);
        KeyExchangeUtil.handleExchangeHashSignatureMessage(context, message);
        KeyExchangeUtil.setSessionId(context);
        KeyExchangeUtil.generateKeySet(context);
    }

    private void splitRemotePublicValues() {
        HybridKeyExchange kex = context.getChooser().getHybridKeyExchange();

        if (kex.getClassicalPublicKeySize() + kex.getPostQuantumEncapsulationSize()
                != message.getPublicValuesLength().getValue()) {
            LOGGER.warn(
                    "Public values length does not match the sum of classical public key size and post quantum encapsulation size.");
        }

        switch (kex.getCombiner()) {
            case POSTQUANTUM_CONCATENATE_CLASSICAL -> {
                message.setPostQuantumKeyEncapsulation(
                        Arrays.copyOfRange(
                                message.getPublicValues().getValue(),
                                0,
                                kex.getPostQuantumEncapsulationSize()));
                message.setClassicalPublicKey(
                        Arrays.copyOfRange(
                                message.getPublicValues().getValue(),
                                kex.getPostQuantumEncapsulationSize(),
                                message.getPublicValuesLength().getValue()));
            }
            case CLASSICAL_CONCATENATE_POSTQUANTUM -> {
                message.setClassicalPublicKey(
                        Arrays.copyOfRange(
                                message.getPublicValues().getValue(),
                                0,
                                kex.getClassicalPublicKeySize()));
                message.setPostQuantumKeyEncapsulation(
                        Arrays.copyOfRange(
                                message.getPublicValues().getValue(),
                                kex.getClassicalPublicKeySize(),
                                message.getPublicValuesLength().getValue()));
            }
        }
    }

    private void updateContextWithRemotePublicValues() {
        HybridKeyExchange kex = context.getChooser().getHybridKeyExchange();
        kex.getClassical().setRemotePublicKey(message.getClassicalPublicKey().getValue());
        kex.getPostQuantum().setEncapsulation(message.getPostQuantumKeyEncapsulation().getValue());
        context.getExchangeHashInputHolder()
                .setHybridServerPublicValues(message.getPublicValues().getValue());
    }

    @Override
    public SshMessageParser<HybridKeyExchangeReplyMessage> getParser(byte[] array) {
        return new HybridKeyExchangeReplyMessageParser(array);
    }

    @Override
    public SshMessageParser<HybridKeyExchangeReplyMessage> getParser(
            byte[] array, int startPosition) {
        return new HybridKeyExchangeReplyMessageParser(array, startPosition);
    }

    @Override
    public SshMessagePreparator<HybridKeyExchangeReplyMessage> getPreparator() {
        return new HybridKeyExchangeReplyMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SshMessageSerializer<HybridKeyExchangeReplyMessage> getSerializer() {
        return new HybridKeyExchangeReplyMessageSerializer(message);
    }
}
