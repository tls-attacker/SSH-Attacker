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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EcdhKeyExchangeInitMessageHandler
        extends SshMessageHandler<EcdhKeyExchangeInitMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public EcdhKeyExchangeInitMessageHandler(SshContext context) {
        super(context);
    }

    public EcdhKeyExchangeInitMessageHandler(
            SshContext context, EcdhKeyExchangeInitMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        context.getChooser()
                .getEcdhKeyExchange()
                .setRemotePublicKey(message.getPublicKey().getValue());
        context.getExchangeHashInputHolder()
                .setEcdhClientPublicKey(message.getPublicKey().getValue());
    }

    @Override
    public EcdhKeyExchangeInitMessageParser getParser(byte[] array, int startPosition) {
        return new EcdhKeyExchangeInitMessageParser(array, startPosition);
    }

    @Override
    public EcdhKeyExchangeInitMessagePreparator getPreparator() {
        return new EcdhKeyExchangeInitMessagePreparator(context.getChooser(), message);
    }

    @Override
    public EcdhKeyExchangeInitMessageSerializer getSerializer() {
        return new EcdhKeyExchangeInitMessageSerializer(message);
    }
}
