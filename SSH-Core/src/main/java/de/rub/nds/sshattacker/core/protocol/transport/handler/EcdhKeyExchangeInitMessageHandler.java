/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.message.EcdhKeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.EcdhKeyExchangeInitMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.EcdhKeyExchangeInitMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.EcdhKeyExchangeInitMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class EcdhKeyExchangeInitMessageHandler
        extends SshMessageHandler<EcdhKeyExchangeInitMessage> {

    @Override
    public void adjustContext(SshContext context, EcdhKeyExchangeInitMessage object) {
        context.getChooser()
                .getEcdhKeyExchange()
                .setRemotePublicKey(object.getEphemeralPublicKey().getValue());
        context.getExchangeHashInputHolder()
                .setEcdhClientPublicKey(object.getEphemeralPublicKey().getValue());
    }

    @Override
    public EcdhKeyExchangeInitMessageParser getParser(byte[] array, SshContext context) {
        return new EcdhKeyExchangeInitMessageParser(array);
    }

    @Override
    public EcdhKeyExchangeInitMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new EcdhKeyExchangeInitMessageParser(array, startPosition);
    }

    public static final EcdhKeyExchangeInitMessagePreparator PREPARATOR =
            new EcdhKeyExchangeInitMessagePreparator();

    public static final EcdhKeyExchangeInitMessageSerializer SERIALIZER =
            new EcdhKeyExchangeInitMessageSerializer();
}
