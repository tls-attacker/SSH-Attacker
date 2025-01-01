/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeOldRequestMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.DhGexKeyExchangeOldRequestMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.DhGexKeyExchangeOldRequestMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.DhGexKeyExchangeOldRequestMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class DhGexKeyExchangeOldRequestMessageHandler
        extends SshMessageHandler<DhGexKeyExchangeOldRequestMessage> {

    @Override
    public void adjustContext(SshContext context, DhGexKeyExchangeOldRequestMessage object) {
        updateContextWithPreferredGroupSize(context, object);
        context.setOldGroupRequestReceived(true);
    }

    private static void updateContextWithPreferredGroupSize(
            SshContext context, DhGexKeyExchangeOldRequestMessage object) {
        context.setPreferredDhGroupSize(object.getPreferredGroupSize().getValue());
        context.getExchangeHashInputHolder()
                .setDhGexPreferredGroupSize(object.getPreferredGroupSize().getValue());
    }

    @Override
    public DhGexKeyExchangeOldRequestMessageParser getParser(byte[] array, SshContext context) {
        return new DhGexKeyExchangeOldRequestMessageParser(array);
    }

    @Override
    public DhGexKeyExchangeOldRequestMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new DhGexKeyExchangeOldRequestMessageParser(array, startPosition);
    }

    public static final DhGexKeyExchangeOldRequestMessagePreparator PREPARATOR =
            new DhGexKeyExchangeOldRequestMessagePreparator();

    public static final DhGexKeyExchangeOldRequestMessageSerializer SERIALIZER =
            new DhGexKeyExchangeOldRequestMessageSerializer();
}
