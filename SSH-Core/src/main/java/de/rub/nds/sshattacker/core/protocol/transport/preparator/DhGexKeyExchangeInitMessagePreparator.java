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
import de.rub.nds.sshattacker.core.crypto.hash.DhGexOldExchangeHash;
import de.rub.nds.sshattacker.core.crypto.hash.ExchangeHash;
import de.rub.nds.sshattacker.core.crypto.kex.DhKeyExchange;
import de.rub.nds.sshattacker.core.crypto.kex.KeyExchange;
import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.math.BigInteger;
import java.util.Optional;
import java.util.Random;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DhGexKeyExchangeInitMessagePreparator extends Preparator<DhGexKeyExchangeInitMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DhGexKeyExchangeInitMessagePreparator(
            SshContext context, DhGexKeyExchangeInitMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        message.setMessageID(MessageIDConstant.SSH_MSG_KEX_DH_GEX_INIT);

        Optional<KeyExchange> keyExchange = context.getKeyExchangeInstance();
        if (keyExchange.isPresent()
                && keyExchange.get() instanceof DhKeyExchange
                && ((DhKeyExchange) keyExchange.get()).areGroupParametersSet()) {
            DhKeyExchange dhKeyExchange = (DhKeyExchange) keyExchange.get();
            dhKeyExchange.generateLocalKeyPair();
            message.setPublicKey(dhKeyExchange.getLocalKeyPair().getPublic().getY(), true);
        } else {
            raisePreparationException(
                    "Key exchange instance is either not present, no DhKeyExchange or does not have its group parameters set, unable to generate a local key pair");
            // TODO: Get public key from config if key exchange instance is not set
            message.setPublicKey(new BigInteger(256, new Random()), true);
        }

        ExchangeHash exchangeHash = context.getExchangeHashInstance();
        if (exchangeHash instanceof DhGexExchangeHash) {
            ((DhGexExchangeHash) exchangeHash)
                    .setClientDHPublicKey(message.getPublicKey().getValue().toByteArray());
        } else if (exchangeHash instanceof DhGexOldExchangeHash) {
            ((DhGexOldExchangeHash) exchangeHash)
                    .setClientDHPublicKey(message.getPublicKey().getValue().toByteArray());
        } else {
            raisePreparationException(
                    "Exchange hash instance is neither DhGexExchangeHash nor DhGexOldExchangeHash or key exchange instance is not present, unable to update exchange hash with local public key");
        }
    }
}
