/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeOldRequestMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.DhGexKeyExchangeOldRequestMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.DhGexKeyExchangeOldRequestMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.DhGexKeyExchangeOldRequestMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DhGexKeyExchangeOldRequestMessageHandler
        extends SshMessageHandler<DhGexKeyExchangeOldRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DhGexKeyExchangeOldRequestMessageHandler(SshContext context) {
        super(context);
    }

    public DhGexKeyExchangeOldRequestMessageHandler(
            SshContext context, DhGexKeyExchangeOldRequestMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        updateContextWithPreferredGroupSize();
        updateExchangeHashWithPreferredGroupSize();
        context.setOldGroupRequestReceived(true);
    }

    private void updateContextWithPreferredGroupSize() {
        context.setPreferredDhGroupSize(message.getPreferredGroupSize().getValue());
    }

    private void updateExchangeHashWithPreferredGroupSize() {
        context.getExchangeHashInputHolder()
                .setDhGexPreferredGroupSize(message.getPreferredGroupSize().getValue());
    }

    @Override
    public SshMessageParser<DhGexKeyExchangeOldRequestMessage> getParser(
            byte[] array, int startPosition) {
        return new DhGexKeyExchangeOldRequestMessageParser(array, startPosition);
    }

    @Override
    public DhGexKeyExchangeOldRequestMessagePreparator getPreparator() {
        return new DhGexKeyExchangeOldRequestMessagePreparator(context.getChooser(), message);
    }

    @Override
    public DhGexKeyExchangeOldRequestMessageSerializer getSerializer() {
        return new DhGexKeyExchangeOldRequestMessageSerializer(message);
    }
}
