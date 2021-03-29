/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.protocol.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.constants.MessageIDConstant;
import de.rub.nds.sshattacker.imported.ec_.EllipticCurveOverFp;
import de.rub.nds.sshattacker.imported.ec_.EllipticCurveSECP256R1;
import de.rub.nds.sshattacker.imported.ec_.FieldElementFp;
import de.rub.nds.sshattacker.imported.ec_.Point;
import de.rub.nds.sshattacker.protocol.message.EcdhKeyExchangeInitMessage;
import de.rub.nds.sshattacker.state.SshContext;
import java.math.BigInteger;
import java.security.SecureRandom;

public class EcdhKeyExchangeInitMessagePreparator extends Preparator<EcdhKeyExchangeInitMessage> {

    public EcdhKeyExchangeInitMessagePreparator(SshContext context, EcdhKeyExchangeInitMessage message) {
        super(context, message);
    }

    public void createKeys() {

        // TODO extract keyexchange
        EllipticCurveOverFp secp256r1 = new EllipticCurveSECP256R1();
        SecureRandom random = new SecureRandom();
        byte[] clientEcdhSecretKey = new byte[32];
        random.nextBytes(clientEcdhSecretKey);
        FieldElementFp a = new FieldElementFp(new BigInteger(1, clientEcdhSecretKey), secp256r1.getBasePointOrder());
        context.setClientEcdhSecretKey(ArrayConverter.bigIntegerToByteArray(a.getData()));
        Point myPoint = secp256r1.mult(new BigInteger(1, context.getClientEcdhSecretKey()), secp256r1.getBasePoint());
        byte[] x = ArrayConverter.bigIntegerToByteArray(myPoint.getX().getData());
        byte[] y = ArrayConverter.bigIntegerToByteArray(myPoint.getY().getData());
        // 04 -> no point compression used; it is not supported by openssh
        context.setClientEcdhPublicKey(ArrayConverter.concatenate(new byte[] { 0x04 }, x, y));
    }

    @Override
    public void prepare() {
        createKeys();
        message.setMessageID(MessageIDConstant.SSH_MSG_KEX_ECDH_INIT.id);
        message.setPublicKey(context.getChooser().getClientEcdhPublicKey());
        message.setPublicKeyLength(context.getChooser().getClientEcdhPublicKey().length);
    }
}
