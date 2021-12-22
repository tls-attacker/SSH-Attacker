/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.sshattacker.core.constants.KeyExchangeFlowType;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.crypto.hash.EcdhExchangeHash;
import de.rub.nds.sshattacker.core.crypto.kex.DhBasedKeyExchange;
import de.rub.nds.sshattacker.core.crypto.kex.EcdhKeyExchange;
import de.rub.nds.sshattacker.core.crypto.kex.XCurveEcdhKeyExchange;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.EcdhKeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.util.Optional;

public class EcdhKeyExchangeInitMessagePreparator
        extends SshMessagePreparator<EcdhKeyExchangeInitMessage> {

    public EcdhKeyExchangeInitMessagePreparator(
            Chooser chooser, EcdhKeyExchangeInitMessage message) {
        super(chooser, message);
    }

    @Override
    public void prepareMessageSpecificContents() {
        getObject().setMessageID(MessageIDConstant.SSH_MSG_KEX_ECDH_INIT);
        Optional<KeyExchangeAlgorithm> keyExchangeAlgorithm =
                chooser.getContext().getKeyExchangeAlgorithm();
        DhBasedKeyExchange keyExchange;
        if (keyExchangeAlgorithm.isPresent()
                && keyExchangeAlgorithm.get().getFlowType() == KeyExchangeFlowType.ECDH) {
            switch (keyExchangeAlgorithm.get()) {
                case CURVE448_SHA512:
                case CURVE25519_SHA256:
                case CURVE25519_SHA256_LIBSSH_ORG:
                    keyExchange = XCurveEcdhKeyExchange.newInstance(keyExchangeAlgorithm.get());
                    break;
                default:
                    keyExchange = EcdhKeyExchange.newInstance(keyExchangeAlgorithm.get());
                    break;
            }
        } else {
            keyExchange =
                    EcdhKeyExchange.newInstance(
                            chooser.getConfig().getDefaultEcdhKeyExchangeAlgortihm());
        }
        keyExchange.generateLocalKeyPair();
        chooser.getContext().setKeyExchangeInstance(keyExchange);
        EcdhExchangeHash ecdhExchangeHash =
                EcdhExchangeHash.from(chooser.getContext().getExchangeHashInstance());
        ecdhExchangeHash.setClientECDHPublicKey(keyExchange.getLocalKeyPair().getPublic());
        chooser.getContext().setExchangeHashInstance(ecdhExchangeHash);

        byte[] encodedPublicKey = keyExchange.getLocalKeyPair().getPublic().getEncoded();
        getObject().setPublicKey(encodedPublicKey, true);
    }
}
