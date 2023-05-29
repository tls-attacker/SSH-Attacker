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
import de.rub.nds.sshattacker.core.protocol.transport.message.EcdhKeyExchangeInitMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EcdhKeyExchangeInitMessageHandler
        extends SshMessageHandler<EcdhKeyExchangeInitMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public EcdhKeyExchangeInitMessageHandler(SshContext context) {
        super(context);
    }

    /*public EcdhKeyExchangeInitMessageHandler(
            SshContext context, EcdhKeyExchangeInitMessage message) {
        super(context, message);
    }*/

    @Override
    public void adjustContext(EcdhKeyExchangeInitMessage message) {
        context.getChooser()
                .getEcdhKeyExchange()
                .setRemotePublicKey(message.getEphemeralPublicKey().getValue());
        context.getExchangeHashInputHolder()
                .setEcdhClientPublicKey(message.getEphemeralPublicKey().getValue());
    }

    /*@Override
    public EcdhKeyExchangeInitMessageParser getParser(byte[] array) {
        return new EcdhKeyExchangeInitMessageParser(array);
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
    }*/
}
