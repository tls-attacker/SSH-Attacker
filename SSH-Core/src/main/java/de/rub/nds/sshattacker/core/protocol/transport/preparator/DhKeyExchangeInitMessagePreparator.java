/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.sshattacker.core.constants.KeyExchangeFlowType;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.crypto.hash.DhNamedExchangeHash;
import de.rub.nds.sshattacker.core.crypto.kex.DhKeyExchange;
import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhKeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.util.Optional;

public class DhKeyExchangeInitMessagePreparator extends Preparator<DhKeyExchangeInitMessage> {

    public DhKeyExchangeInitMessagePreparator(
            SshContext context, DhKeyExchangeInitMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        // TODO: Handle default value for key exchange algorithm in Config
        Optional<KeyExchangeAlgorithm> keyExchangeAlgorithm = context.getKeyExchangeAlgorithm();
        DhKeyExchange keyExchange;
        if (keyExchangeAlgorithm.isPresent()
                && keyExchangeAlgorithm.get().getFlowType() == KeyExchangeFlowType.DIFFIE_HELLMAN) {
            keyExchange = DhKeyExchange.newInstance(keyExchangeAlgorithm.get());
        } else {
            raisePreparationException(
                    "Key exchange algorithm not negotiated or unexpected flow type, unable to generate a local key pair");
            keyExchange =
                    DhKeyExchange.newInstance(KeyExchangeAlgorithm.DIFFIE_HELLMAN_GROUP14_SHA256);
        }
        keyExchange.generateLocalKeyPair();
        context.setKeyExchangeInstance(keyExchange);

        DhNamedExchangeHash dhNamedExchangeHash =
                DhNamedExchangeHash.from(context.getExchangeHashInstance());
        dhNamedExchangeHash.setClientDHPublicKey(keyExchange.getLocalKeyPair().getPublic());
        context.setExchangeHashInstance(dhNamedExchangeHash);

        getObject().setMessageID(MessageIDConstant.SSH_MSG_KEXDH_INIT);
        getObject().setPublicKey(keyExchange.getLocalKeyPair().getPublic().getY(), true);
    }
}
