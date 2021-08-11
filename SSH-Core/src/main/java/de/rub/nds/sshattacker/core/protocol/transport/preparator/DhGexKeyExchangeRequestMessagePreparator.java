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
import de.rub.nds.sshattacker.core.exceptions.PreparationException;
import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeRequestMessage;
import de.rub.nds.sshattacker.core.state.SshContext;

public class DhGexKeyExchangeRequestMessagePreparator
        extends Preparator<DhGexKeyExchangeRequestMessage> {

    public DhGexKeyExchangeRequestMessagePreparator(
            SshContext context, DhGexKeyExchangeRequestMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        DhKeyExchange keyExchange =
                DhKeyExchange.newInstance(
                        context.getKeyExchangeAlgorithm().orElseThrow(PreparationException::new));
        context.setKeyExchangeInstance(keyExchange);
        DhGexExchangeHash dhGexExchangeHash =
                DhGexExchangeHash.from(context.getExchangeHashInstance());
        dhGexExchangeHash.setMinimalGroupSize(context.getChooser().getMinimalDHGroupSize());
        dhGexExchangeHash.setPreferredGroupSize(context.getChooser().getPreferredDHGroupSize());
        dhGexExchangeHash.setMaximalGroupSize(context.getChooser().getMaximalDHGroupSize());
        context.setExchangeHashInstance(dhGexExchangeHash);

        message.setMessageID(MessageIDConstant.SSH_MSG_KEX_DH_GEX_REQUEST);
        message.setMinimalGroupSize(context.getChooser().getMinimalDHGroupSize());
        message.setPreferredGroupSize(context.getChooser().getPreferredDHGroupSize());
        message.setMaximalGroupSize(context.getChooser().getMaximalDHGroupSize());
    }
}
