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
import de.rub.nds.sshattacker.core.protocol.transport.message.DhKeyExchangeInitMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DhKeyExchangeInitMessageHandler extends SshMessageHandler<DhKeyExchangeInitMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DhKeyExchangeInitMessageHandler(SshContext context) {
        super(context);
    }

    /*public DhKeyExchangeInitMessageHandler(SshContext context, DhKeyExchangeInitMessage message) {
        super(context, message);
    }*/

    @Override
    public void adjustContext(DhKeyExchangeInitMessage message) {
        sshContext
                .getChooser()
                .getDhKeyExchange()
                .setRemotePublicKey(message.getEphemeralPublicKey().getValue());
        sshContext
                .getExchangeHashInputHolder()
                .setDhClientPublicKey(message.getEphemeralPublicKey().getValue());
    }

    /*@Override
    public SshMessageParser<DhKeyExchangeInitMessage> getParser(byte[] array) {
        return new DhKeyExchangeInitMessageParser(array);
    }

    @Override
    public SshMessageParser<DhKeyExchangeInitMessage> getParser(byte[] array, int startPosition) {
        return new DhKeyExchangeInitMessageParser(array, startPosition);
    }

    @Override
    public DhKeyExchangeInitMessagePreparator getPreparator() {
        return new DhKeyExchangeInitMessagePreparator(context.getChooser(), message);
    }

    @Override
    public DhKeyExchangeInitMessageSerializer getSerializer() {
        return new DhKeyExchangeInitMessageSerializer(message);
    }*/
}
