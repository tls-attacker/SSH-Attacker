/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.crypto.hash.DhGexExchangeHash;
import de.rub.nds.sshattacker.core.crypto.hash.DhGexOldExchangeHash;
import de.rub.nds.sshattacker.core.crypto.hash.ExchangeHash;
import de.rub.nds.sshattacker.core.crypto.kex.DhKeyExchange;
import de.rub.nds.sshattacker.core.crypto.kex.KeyExchange;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeGroupMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.DhGexKeyExchangeGroupMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.DhGexKeyExchangeGroupMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.DhGexKeyExchangeGroupMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DhGexKeyExchangeGroupMessageHandler
        extends SshMessageHandler<DhGexKeyExchangeGroupMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DhGexKeyExchangeGroupMessageHandler(SshContext context) {
        super(context);
    }

    public DhGexKeyExchangeGroupMessageHandler(
            SshContext context, DhGexKeyExchangeGroupMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        setGroupParametersFromMessage(message);
        updateExchangeHashWithGroupParameters(message);
    }

    private void setGroupParametersFromMessage(DhGexKeyExchangeGroupMessage msg) {
        if (context.getKeyExchangeInstance().isPresent()) {
            KeyExchange keyExchange = context.getKeyExchangeInstance().get();
            if (keyExchange instanceof DhKeyExchange) {
                DhKeyExchange dhKeyExchange = (DhKeyExchange) keyExchange;
                dhKeyExchange.setModulus(msg.getGroupModulus().getValue());
                dhKeyExchange.setGenerator(msg.getGroupGenerator().getValue());
            } else {
                raiseAdjustmentException(
                        "Key exchange instance is not an DhKeyExchange, unable to set group modulus and generator for the key exchange instance");
            }
        } else {
            raiseAdjustmentException(
                    "Key exchange instance is not present, unable to set group modulus and generator for the key exchange instance");
        }
    }

    private void updateExchangeHashWithGroupParameters(DhGexKeyExchangeGroupMessage msg) {
        ExchangeHash exchangeHash = context.getExchangeHashInstance();
        if (exchangeHash instanceof DhGexExchangeHash) {
            DhGexExchangeHash dhGexExchangeHash = (DhGexExchangeHash) exchangeHash;
            dhGexExchangeHash.setGroupModulus(msg.getGroupModulus().getValue());
            dhGexExchangeHash.setGroupGenerator(msg.getGroupGenerator().getValue());
        } else if (exchangeHash instanceof DhGexOldExchangeHash) {
            DhGexOldExchangeHash dhGexOldExchangeHash = (DhGexOldExchangeHash) exchangeHash;
            dhGexOldExchangeHash.setGroupModulus(msg.getGroupModulus().getValue());
            dhGexOldExchangeHash.setGroupGenerator(msg.getGroupGenerator().getValue());
        } else {
            raiseAdjustmentException(
                    "Exchange hash instance is neither DhGexExchangeHash nor DhGexOldExchangeHash, unable to update exchange hash");
        }
    }

    @Override
    public DhGexKeyExchangeGroupMessageParser getParser(byte[] array, int startPosition) {
        return new DhGexKeyExchangeGroupMessageParser(array, startPosition);
    }

    @Override
    public SshMessagePreparator<DhGexKeyExchangeGroupMessage> getPreparator() {
        return new DhGexKeyExchangeGroupMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SshMessageSerializer<DhGexKeyExchangeGroupMessage> getSerializer() {
        return new DhGexKeyExchangeGroupMessageSerializer(message);
    }
}
