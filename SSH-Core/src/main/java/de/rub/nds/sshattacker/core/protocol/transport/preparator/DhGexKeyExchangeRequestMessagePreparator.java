/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.crypto.hash.DhGexExchangeHash;
import de.rub.nds.sshattacker.core.crypto.kex.DhKeyExchange;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeRequestMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DhGexKeyExchangeRequestMessagePreparator
        extends SshMessagePreparator<DhGexKeyExchangeRequestMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DhGexKeyExchangeRequestMessagePreparator(
            SshContext context, DhGexKeyExchangeRequestMessage message) {
        super(context, message);
    }

    @Override
    public void prepareMessageSpecificContents() {
        getObject().setMessageID(MessageIDConstant.SSH_MSG_KEX_DH_GEX_REQUEST);
        if (context.getKeyExchangeAlgorithm().isPresent()) {
            DhKeyExchange keyExchange =
                    DhKeyExchange.newInstance(context.getKeyExchangeAlgorithm().get());
            context.setKeyExchangeInstance(keyExchange);
        } else {
            raisePreparationException(
                    "Unable to instantiate a new DH key exchange, the negotiated key exchange algorithm is not set");
        }

        DhGexExchangeHash dhGexExchangeHash =
                DhGexExchangeHash.from(context.getExchangeHashInstance());
        dhGexExchangeHash.setMinimalGroupSize(context.getChooser().getMinimalDHGroupSize());
        dhGexExchangeHash.setPreferredGroupSize(context.getChooser().getPreferredDHGroupSize());
        dhGexExchangeHash.setMaximalGroupSize(context.getChooser().getMaximalDHGroupSize());
        context.setExchangeHashInstance(dhGexExchangeHash);

        getObject().setMinimalGroupSize(context.getChooser().getMinimalDHGroupSize());
        getObject().setPreferredGroupSize(context.getChooser().getPreferredDHGroupSize());
        getObject().setMaximalGroupSize(context.getChooser().getMaximalDHGroupSize());
    }
}
