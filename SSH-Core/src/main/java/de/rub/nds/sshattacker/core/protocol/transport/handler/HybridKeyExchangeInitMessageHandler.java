/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.crypto.kex.HybridKeyExchange;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.message.HybridKeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.HybridKeyExchangeInitMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.HybridKeyExchangeInitMessagePreperator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.HybridKeyExchangeInitMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HybridKeyExchangeInitMessageHandler
        extends SshMessageHandler<HybridKeyExchangeInitMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public HybridKeyExchangeInitMessageHandler(SshContext context) {
        super(context);
    }

    public HybridKeyExchangeInitMessageHandler(
            SshContext context, HybridKeyExchangeInitMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        splitRemotePublicValues();
        updateContextWithRemotePublicValues();
    }

    private void splitRemotePublicValues() {
        HybridKeyExchange kex = context.getChooser().getHybridKeyExchange();

        if (kex.getClassicalPublicKeySize() + kex.getPostQuantumPublicKeySize()
                != message.getPublicValuesLength().getValue()) {
            LOGGER.warn(
                    "Public values length does not match the sum of classical and post quantum public key sizes.");
        }

        switch (kex.getCombiner()) {
            case POSTQUANTUM_CONCATENATE_CLASSICAL -> {
                message.setPostQuantumPublicKey(
                        Arrays.copyOfRange(
                                message.getPublicValues().getValue(),
                                0,
                                kex.getPostQuantumPublicKeySize()));
                message.setClassicalPublicKey(
                        Arrays.copyOfRange(
                                message.getPublicValues().getValue(),
                                kex.getPostQuantumPublicKeySize(),
                                message.getPublicValuesLength().getValue()));
            }
            case CLASSICAL_CONCATENATE_POSTQUANTUM -> {
                message.setClassicalPublicKey(
                        Arrays.copyOfRange(
                                message.getPublicValues().getValue(),
                                0,
                                kex.getClassicalPublicKeySize()));
                message.setPostQuantumPublicKey(
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
        kex.getPostQuantum().setPublicKey(message.getPostQuantumPublicKey().getValue());
        context.getExchangeHashInputHolder()
                .setHybridClientPublicValues(message.getPublicValues().getValue());
    }

    @Override
    public HybridKeyExchangeInitMessageParser getParser(byte[] array) {
        return new HybridKeyExchangeInitMessageParser(array);
    }

    @Override
    public HybridKeyExchangeInitMessageParser getParser(byte[] array, int startPosition) {
        return new HybridKeyExchangeInitMessageParser(array, startPosition);
    }

    @Override
    public HybridKeyExchangeInitMessagePreperator getPreparator() {
        return new HybridKeyExchangeInitMessagePreperator(context.getChooser(), message);
    }

    @Override
    public HybridKeyExchangeInitMessageSerializer getSerializer() {
        return new HybridKeyExchangeInitMessageSerializer(message);
    }
}
