/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.crypto.hash.EcdhExchangeHash;
import de.rub.nds.sshattacker.core.crypto.kex.DhBasedKeyExchange;
import de.rub.nds.sshattacker.core.crypto.kex.EcdhKeyExchange;
import de.rub.nds.sshattacker.core.crypto.kex.XCurveEcdhKeyExchange;
import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.EcdhKeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.util.Optional;

public class EcdhKeyExchangeInitMessagePreparator extends Preparator<EcdhKeyExchangeInitMessage> {

    public EcdhKeyExchangeInitMessagePreparator(
            SshContext context, EcdhKeyExchangeInitMessage message) {
        super(context, message);
    }

    @Override
    public void prepare() {
        Optional<KeyExchangeAlgorithm> keyExchangeAlgorithm = context.getKeyExchangeAlgorithm();
        DhBasedKeyExchange keyExchange;
        if (keyExchangeAlgorithm.isPresent()) {
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
            raisePreparationException(
                    "Key exchange algorithm not negotiate, unable to generate a local key pair");
            keyExchange = EcdhKeyExchange.newInstance(KeyExchangeAlgorithm.ECDH_SHA2_NISTP256);
        }
        keyExchange.generateLocalKeyPair();
        context.setKeyExchangeInstance(keyExchange);
        EcdhExchangeHash ecdhExchangeHash =
                EcdhExchangeHash.from(context.getExchangeHashInstance());
        ecdhExchangeHash.setClientECDHPublicKey(keyExchange.getLocalKeyPair().getPublic());
        context.setExchangeHashInstance(ecdhExchangeHash);

        byte[] encodedPublicKey = keyExchange.getLocalKeyPair().getPublic().getEncoded();
        message.setMessageID(MessageIDConstant.SSH_MSG_KEX_ECDH_INIT);
        message.setPublicKey(encodedPublicKey, true);
    }
}
