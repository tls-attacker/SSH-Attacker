/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.crypto.kex.HybridKeyExchange;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.message.HybridKeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.HybridKeyExchangeInitMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.HybridKeyExchangeInitMessagePreperator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.HybridKeyExchangeInitMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class HybridKeyExchangeInitMessageHandler
        extends SshMessageHandler<HybridKeyExchangeInitMessage> {

    public HybridKeyExchangeInitMessageHandler(SshContext context) {
        super(context);
    }

    public HybridKeyExchangeInitMessageHandler(
            SshContext context, HybridKeyExchangeInitMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        context.getChooser()
                .getHybridKeyExchange()
                .getKeyAgreement()
                .setRemotePublicKey(message.getAgreementPublicKey().getValue());
        context.getChooser()
                .getHybridKeyExchange()
                .getKeyEncapsulation()
                .setRemotePublicKey(message.getEncapsulationPublicKey().getValue());
        context.getExchangeHashInputHolder()
                .setHybridClientPublicKey(
                        ArrayConverter.concatenate(
                                message.getEncapsulationPublicKey().getValue(),
                                message.getAgreementPublicKey().getValue()));
    }

    @Override
    public HybridKeyExchangeInitMessageParser getParser(byte[] array) {
        HybridKeyExchange kex = context.getChooser().getHybridKeyExchange();
        return new HybridKeyExchangeInitMessageParser(
                array,
                kex.getPkCombiner(),
                kex.getPkAgreementLength(),
                kex.getPkEncapsulationLength());
    }

    @Override
    public HybridKeyExchangeInitMessageParser getParser(byte[] array, int startPosition) {
        HybridKeyExchange kex = context.getChooser().getHybridKeyExchange();
        return new HybridKeyExchangeInitMessageParser(
                array,
                startPosition,
                kex.getPkCombiner(),
                kex.getPkAgreementLength(),
                kex.getPkEncapsulationLength());
    }

    @Override
    public HybridKeyExchangeInitMessagePreperator getPreparator() {
        HybridKeyExchange kex = context.getChooser().getHybridKeyExchange();
        return new HybridKeyExchangeInitMessagePreperator(
                context.getChooser(), message, kex.getPkCombiner());
    }

    @Override
    public HybridKeyExchangeInitMessageSerializer getSerializer() {
        HybridKeyExchange kex = context.getChooser().getHybridKeyExchange();
        return new HybridKeyExchangeInitMessageSerializer(message, kex.getPkCombiner());
    }
}
