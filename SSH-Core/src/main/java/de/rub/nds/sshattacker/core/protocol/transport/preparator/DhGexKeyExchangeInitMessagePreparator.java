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
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.util.Optional;
import java.util.Random;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DhGexKeyExchangeInitMessagePreparator
        extends SshMessagePreparator<DhGexKeyExchangeInitMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DhGexKeyExchangeInitMessagePreparator(
            Chooser chooser, DhGexKeyExchangeInitMessage message) {
        super(chooser, message);
    }

    @Override
    public void prepareMessageSpecificContents() {
        getObject().setMessageID(MessageIDConstant.SSH_MSG_KEX_DH_GEX_INIT);
        Optional<KeyExchange> keyExchange = chooser.getContext().getKeyExchangeInstance();
        if (keyExchange.isPresent() && keyExchange.get() instanceof DhKeyExchange) {
            DhKeyExchange dhKeyExchange = (DhKeyExchange) keyExchange.get();
            if (!(dhKeyExchange.areGroupParametersSet())) {
                dhKeyExchange.setModulus(
                        chooser.getConfig().getDefaultDHGexKeyExchangeGroup().getModulus());
                dhKeyExchange.setGenerator(
                        chooser.getConfig().getDefaultDHGexKeyExchangeGroup().getGenerator());
            }
            ;
            dhKeyExchange.generateLocalKeyPair();
            getObject().setPublicKey(dhKeyExchange.getLocalKeyPair().getPublic().getY(), true);
        } else {
            // ToDo Maybe implement and raise new "missingContextContents" Exception
            DhKeyExchange dhKeyExchange =
                    (DhKeyExchange)
                            DhKeyExchange.newInstance(
                                    (chooser.getRandomKeyExchangeAlgorithm(
                                            new Random(),
                                            chooser.getAllSupportedDH_DHGEKeyExchange())));
            if (!(dhKeyExchange.areGroupParametersSet())) {
                dhKeyExchange.setModulus(
                        chooser.getConfig().getDefaultDHGexKeyExchangeGroup().getModulus());
                dhKeyExchange.setGenerator(
                        chooser.getConfig().getDefaultDHGexKeyExchangeGroup().getGenerator());
            }
            ;
            dhKeyExchange.generateLocalKeyPair();
            getObject().setPublicKey(dhKeyExchange.getLocalKeyPair().getPublic().getY(), true);
            chooser.getContext().setKeyExchangeInstance(dhKeyExchange);
        }

        ExchangeHash exchangeHash = chooser.getContext().getExchangeHashInstance();
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
            chooser.getContext()
                    .setExchangeHashInstance(
                            DhGexExchangeHash.from(chooser.getContext().getExchangeHashInstance()));
            ExchangeHash dhexchangeHash = chooser.getContext().getExchangeHashInstance();
            ((DhGexExchangeHash) dhexchangeHash)
                    .setClientDHPublicKey(getObject().getPublicKey().getValue().toByteArray());
        }
    }
}
