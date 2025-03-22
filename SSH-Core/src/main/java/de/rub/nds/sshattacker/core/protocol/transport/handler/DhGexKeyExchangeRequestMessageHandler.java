/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.crypto.hash.ExchangeHashInputHolder;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeRequestMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.DhGexKeyExchangeRequestMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.DhGexKeyExchangeRequestMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.DhGexKeyExchangeRequestMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class DhGexKeyExchangeRequestMessageHandler
        extends SshMessageHandler<DhGexKeyExchangeRequestMessage> {

    @Override
    public void adjustContext(SshContext context, DhGexKeyExchangeRequestMessage object) {
        updateContextWithAcceptableGroupSize(context, object);
        updateExchangeHashWithAcceptableGroupSize(context, object);
        context.setOldGroupRequestReceived(false);
    }

    private static void updateContextWithAcceptableGroupSize(
            SshContext context, DhGexKeyExchangeRequestMessage object) {
        context.setMinimalDhGroupSize(object.getMinimalGroupSize().getValue());
        context.setPreferredDhGroupSize(object.getPreferredGroupSize().getValue());
        context.setMaximalDhGroupSize(object.getMaximalGroupSize().getValue());
    }

    private static void updateExchangeHashWithAcceptableGroupSize(
            SshContext context, DhGexKeyExchangeRequestMessage object) {
        ExchangeHashInputHolder inputHolder = context.getExchangeHashInputHolder();
        inputHolder.setDhGexMinimalGroupSize(object.getMinimalGroupSize().getValue());
        inputHolder.setDhGexPreferredGroupSize(object.getPreferredGroupSize().getValue());
        inputHolder.setDhGexMaximalGroupSize(object.getMaximalGroupSize().getValue());
    }

    @Override
    public DhGexKeyExchangeRequestMessageParser getParser(byte[] array, SshContext context) {
        return new DhGexKeyExchangeRequestMessageParser(array);
    }

    @Override
    public DhGexKeyExchangeRequestMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new DhGexKeyExchangeRequestMessageParser(array, startPosition);
    }

    public static final DhGexKeyExchangeRequestMessagePreparator PREPARATOR =
            new DhGexKeyExchangeRequestMessagePreparator();

    public static final DhGexKeyExchangeRequestMessageSerializer SERIALIZER =
            new DhGexKeyExchangeRequestMessageSerializer();
}
