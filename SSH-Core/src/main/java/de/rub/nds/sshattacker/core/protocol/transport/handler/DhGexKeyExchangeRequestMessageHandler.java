/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.crypto.hash.ExchangeHashInputHolder;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeRequestMessage;

public class DhGexKeyExchangeRequestMessageHandler
        extends SshMessageHandler<DhGexKeyExchangeRequestMessage> {

    public DhGexKeyExchangeRequestMessageHandler(SshContext context) {
        super(context);
    }

    /*public DhGexKeyExchangeRequestMessageHandler(
            SshContext context, DhGexKeyExchangeRequestMessage message) {
        super(context, message);
    }*/

    @Override
    public void adjustContext(DhGexKeyExchangeRequestMessage message) {
        updateContextWithAcceptableGroupSize(message);
        updateExchangeHashWithAcceptableGroupSize(message);
        context.setOldGroupRequestReceived(false);
    }

    private void updateContextWithAcceptableGroupSize(DhGexKeyExchangeRequestMessage message) {
        context.setMinimalDhGroupSize(message.getMinimalGroupSize().getValue());
        context.setPreferredDhGroupSize(message.getPreferredGroupSize().getValue());
        context.setMaximalDhGroupSize(message.getMaximalGroupSize().getValue());
    }

    private void updateExchangeHashWithAcceptableGroupSize(DhGexKeyExchangeRequestMessage message) {
        ExchangeHashInputHolder inputHolder = context.getExchangeHashInputHolder();
        inputHolder.setDhGexMinimalGroupSize(message.getMinimalGroupSize().getValue());
        inputHolder.setDhGexPreferredGroupSize(message.getPreferredGroupSize().getValue());
        inputHolder.setDhGexMaximalGroupSize(message.getMaximalGroupSize().getValue());
    }

    /*@Override
    public SshMessageParser<DhGexKeyExchangeRequestMessage> getParser(byte[] array) {
        return new DhGexKeyExchangeRequestMessageParser(array);
    }

    @Override
    public SshMessageParser<DhGexKeyExchangeRequestMessage> getParser(
            byte[] array, int startPosition) {
        return new DhGexKeyExchangeRequestMessageParser(array, startPosition);
    }

    @Override
    public DhGexKeyExchangeRequestMessagePreparator getPreparator() {
        return new DhGexKeyExchangeRequestMessagePreparator(context.getChooser(), message);
    }

    @Override
    public DhGexKeyExchangeRequestMessageSerializer getSerializer() {
        return new DhGexKeyExchangeRequestMessageSerializer(message);
    }*/
}
