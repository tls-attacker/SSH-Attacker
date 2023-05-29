/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.message.HybridKeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.protocol.util.KeyExchangeUtil;

public class HybridKeyExchangeInitMessageHandler
        extends SshMessageHandler<HybridKeyExchangeInitMessage> {

    public HybridKeyExchangeInitMessageHandler(SshContext context) {
        super(context);
    }

    /*public HybridKeyExchangeInitMessageHandler(
            SshContext context, HybridKeyExchangeInitMessage message) {
        super(context, message);
    }*/

    @Override
    public void adjustContext(HybridKeyExchangeInitMessage message) {
        context.getChooser()
                .getHybridKeyExchange()
                .getKeyAgreement()
                .setRemotePublicKey(message.getAgreementPublicKey().getValue());
        context.getChooser()
                .getHybridKeyExchange()
                .getKeyEncapsulation()
                .setRemotePublicKey(message.getEncapsulationPublicKey().getValue());
        byte[] combined;
        switch (context.getChooser().getHybridKeyExchange().getCombiner()) {
            case POSTQUANTUM_CONCATENATE_CLASSICAL:
                combined =
                        KeyExchangeUtil.concatenateHybridKeys(
                                message.getEncapsulationPublicKey().getValue(),
                                message.getAgreementPublicKey().getValue());
                context.getExchangeHashInputHolder().setHybridClientPublicKey(combined);
                break;
            case CLASSICAL_CONCATENATE_POSTQUANTUM:
                combined =
                        KeyExchangeUtil.concatenateHybridKeys(
                                message.getAgreementPublicKey().getValue(),
                                message.getEncapsulationPublicKey().getValue());
                context.getExchangeHashInputHolder().setHybridClientPublicKey(combined);
                break;
            default:
                LOGGER.warn("combiner is not supported. Can not set Hybrid Key.");
                break;
        }
    }

    /*@Override
    public HybridKeyExchangeInitMessageParser getParser(byte[] array) {
        HybridKeyExchange kex = context.getChooser().getHybridKeyExchange();
        return new HybridKeyExchangeInitMessageParser(
                array,
                kex.getCombiner(),
                kex.getPkAgreementLength(),
                kex.getPkEncapsulationLength());
    }

    @Override
    public HybridKeyExchangeInitMessageParser getParser(byte[] array, int startPosition) {
        HybridKeyExchange kex = context.getChooser().getHybridKeyExchange();
        return new HybridKeyExchangeInitMessageParser(
                array,
                startPosition,
                kex.getCombiner(),
                kex.getPkAgreementLength(),
                kex.getPkEncapsulationLength());
    }

    @Override
    public HybridKeyExchangeInitMessagePreperator getPreparator() {
        HybridKeyExchange kex = context.getChooser().getHybridKeyExchange();
        return new HybridKeyExchangeInitMessagePreperator(
                context.getChooser(), message, kex.getCombiner());
    }

    @Override
    public HybridKeyExchangeInitMessageSerializer getSerializer() {
        HybridKeyExchange kex = context.getChooser().getHybridKeyExchange();
        return new HybridKeyExchangeInitMessageSerializer(message, kex.getCombiner());
    }*/
}
