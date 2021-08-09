/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.crypto.hash.DhGexExchangeHash;
import de.rub.nds.sshattacker.core.crypto.hash.DhGexOldExchangeHash;
import de.rub.nds.sshattacker.core.crypto.hash.ExchangeHash;
import de.rub.nds.sshattacker.core.crypto.kex.DhKeyExchange;
import de.rub.nds.sshattacker.core.exceptions.AdjustmentException;
import de.rub.nds.sshattacker.core.protocol.common.Handler;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeGroupMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DhGexKeyExchangeGroupMessageHandler extends Handler<DhGexKeyExchangeGroupMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DhGexKeyExchangeGroupMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void handle(DhGexKeyExchangeGroupMessage msg) {
        if (context.getKeyExchangeInstance().isPresent()) {
            DhKeyExchange dhKeyExchange = (DhKeyExchange) context.getKeyExchangeInstance().get();
            dhKeyExchange.setModulus(msg.getGroupModulus().getValue());
            dhKeyExchange.setGenerator(msg.getGroupGenerator().getValue());
        } else {
            String errorMsg = "Key exchange instance is not present, unable to set group modulus and generator for the key exchange instance";
            if(context.getConfig().getAvoidAdjustmentExceptions()) {
                LOGGER.warn(errorMsg);
            } else {
                throw new AdjustmentException(errorMsg);
            }
        }

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
            String errorMsg = "Exchange hash instance is neither DhGexExchangeHash nor DhGexOldExchangeHash or key exchange instance is not present, unable to update exchange hash";
            if(context.getConfig().getAvoidAdjustmentExceptions()) {
                LOGGER.warn(errorMsg);
            } else {
                throw new AdjustmentException(errorMsg);
            }
        }
    }
}
