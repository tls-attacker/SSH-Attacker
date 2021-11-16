/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.crypto.hash.DhGexExchangeHash;
import de.rub.nds.sshattacker.core.crypto.hash.DhGexOldExchangeHash;
import de.rub.nds.sshattacker.core.crypto.hash.ExchangeHash;
import de.rub.nds.sshattacker.core.crypto.kex.DhKeyExchange;
import de.rub.nds.sshattacker.core.crypto.kex.KeyExchange;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhGexKeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.util.Optional;
import java.util.Random;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DhGexKeyExchangeInitMessagePreparator
        extends SshMessagePreparator<DhGexKeyExchangeInitMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DhGexKeyExchangeInitMessagePreparator(
            SshContext context, DhGexKeyExchangeInitMessage message) {
        super(context, message);
    }

    @Override
    public void prepareMessageSpecificContents() {
        getObject().setMessageID(MessageIDConstant.SSH_MSG_KEX_DH_GEX_INIT);
        Optional<KeyExchange> keyExchange = context.getKeyExchangeInstance();
        if (keyExchange.isPresent() && keyExchange.get() instanceof DhKeyExchange) {
            DhKeyExchange dhKeyExchange = (DhKeyExchange) keyExchange.get();
            if (!(dhKeyExchange.areGroupParametersSet())) {
                dhKeyExchange.setModulus(
                        context.getConfig().getDefaultDHGexKeyExchangeGroup().getModulus());
                dhKeyExchange.setGenerator(
                        context.getConfig().getDefaultDHGexKeyExchangeGroup().getGenerator());
            }
            ;
            dhKeyExchange.generateLocalKeyPair();
            getObject().setPublicKey(dhKeyExchange.getLocalKeyPair().getPublic().getY(), true);
        } else {
            // ToDo Maybe implement and raise new "missingContextContents" Exception
            DhKeyExchange dhKeyExchange =
                    (DhKeyExchange)
                            DhKeyExchange.newInstance(
                                    (context.getChooser()
                                            .getRandomKeyExchangeAlgorithm(
                                                    new Random(),
                                                    context.getChooser()
                                                            .getAllSupportedDH_DHGEKeyExchange())));
            if (!(dhKeyExchange.areGroupParametersSet())) {
                dhKeyExchange.setModulus(
                        context.getConfig().getDefaultDHGexKeyExchangeGroup().getModulus());
                dhKeyExchange.setGenerator(
                        context.getConfig().getDefaultDHGexKeyExchangeGroup().getGenerator());
            }
            ;
            dhKeyExchange.generateLocalKeyPair();
            getObject().setPublicKey(dhKeyExchange.getLocalKeyPair().getPublic().getY(), true);
            context.setKeyExchangeInstance(dhKeyExchange);
        }
        ExchangeHash exchangeHash = context.getExchangeHashInstance();
        if (exchangeHash instanceof DhGexExchangeHash) {
            ((DhGexExchangeHash) exchangeHash)
                    .setClientDHPublicKey(getObject().getPublicKey().getValue().toByteArray());
        } else if (exchangeHash instanceof DhGexOldExchangeHash) {
            ((DhGexOldExchangeHash) exchangeHash)
                    .setClientDHPublicKey(getObject().getPublicKey().getValue().toByteArray());
        } else {
            // throw "missingContextContents" Exception "Exchange hash instance is neither
            // DhGexExchangeHash nor DhGexOldExchangeHash or key exchange instance is not present,
            // unable to update exchange hash with local public key");
            context.setExchangeHashInstance(
                    DhGexExchangeHash.from(context.getExchangeHashInstance()));
            ExchangeHash dhexchangeHash = context.getExchangeHashInstance();
            ((DhGexExchangeHash) dhexchangeHash)
                    .setClientDHPublicKey(getObject().getPublicKey().getValue().toByteArray());
        }
    }
}
