/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.crypto.hash.DhGexOldExchangeHash;
import de.rub.nds.sshattacker.core.crypto.kex.DhKeyExchange;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeOldRequestMessage;
import de.rub.nds.sshattacker.core.state.SshContext;

public class DhGexKeyExchangeOldRequestMessagePreparator
        extends SshMessagePreparator<DhGexKeyExchangeOldRequestMessage> {

    public DhGexKeyExchangeOldRequestMessagePreparator(
            SshContext context, DhGexKeyExchangeOldRequestMessage message) {
        super(context, message);
    }

    @Override
    public void prepareMessageSpecificContents() {
        getObject().setMessageID(MessageIDConstant.SSH_MSG_KEX_DH_GEX_REQUEST_OLD);
        if (context.getKeyExchangeAlgorithm().isPresent()) {
            DhKeyExchange keyExchange =
                    DhKeyExchange.newInstance(context.getKeyExchangeAlgorithm().get());
            context.setKeyExchangeInstance(keyExchange);
        } else {
            raisePreparationException(
                    "Unable to instantiate a new DH key exchange, the negotiated key exchange algorithm is not set");
        }

        DhGexOldExchangeHash dhGexOldExchangeHash =
                DhGexOldExchangeHash.from(context.getExchangeHashInstance());
        dhGexOldExchangeHash.setPreferredGroupSize(context.getChooser().getPreferredDHGroupSize());
        context.setExchangeHashInstance(dhGexOldExchangeHash);

        getObject().setPreferredGroupSize(context.getChooser().getPreferredDHGroupSize());
    }
}
