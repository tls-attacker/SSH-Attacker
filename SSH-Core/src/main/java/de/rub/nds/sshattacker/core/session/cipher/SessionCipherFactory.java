/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.session.cipher;

/*import de.rub.nds.sshattacker.core.constants.AlgorithmResolver;
import de.rub.nds.sshattacker.core.constants.CipherSuite;
import de.rub.nds.sshattacker.core.constants.CipherType;
import de.rub.nds.sshattacker.core.constants.ExtensionType;*/

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SessionCipherFactory {

    private static final Logger LOGGER = LogManager.getLogger();

    /*public static SessionCipher getSessionCipher(
            SshContext sshContext, KeySet keySet, CipherSuite cipherSuite, byte[] connectionId) {
        try {
            if (sshContext.getChooser().getSelectedCipherSuite() == null
                    || !cipherSuite.isImplemented()) {
                LOGGER.warn(
                        "Cipher "
                                + cipherSuite.name()
                                + " not implemented. Using Null Cipher instead");
                return getNullCipher(sshContext);
            } else {
                CipherType type = AlgorithmResolver.getCipherType(cipherSuite);
                CipherState state =
                        new CipherState(
                                sshContext.getChooser().getSelectedProtocolVersion(),
                                cipherSuite,
                                keySet,
                                sshContext.isExtensionNegotiated(ExtensionType.ENCRYPT_THEN_MAC),
                                connectionId);
                switch (type) {
                    case AEAD:
                        return new SessionAEADCipher(sshContext, state);
                    case BLOCK:
                        return new SessionBlockCipher(sshContext, state);
                    case STREAM:
                        return new SessionStreamCipher(sshContext, state);
                    default:
                        LOGGER.warn("UnknownCipherType:" + type.name());
                        return new SessionNullCipher(sshContext, state);
                }
            }
        } catch (Exception e) {
            LOGGER.debug(
                    "Could not create RecordCipher from the current Context! Creating null Cipher",
                    e);
            return getNullCipher(sshContext);
        }
    }*/

    /*public static SessionCipher getSessionCipher(
            TlsContext tlsContext, KeySet keySet, boolean isForEncryption) {
        return getSessionCipher(
                tlsContext,
                keySet,
                tlsContext.getChooser().getSelectedCipherSuite(),
                isForEncryption
                        ? tlsContext.getWriteConnectionId()
                        : tlsContext.getReadConnectionId());
    }*/

    public static SessionNullCipher getNullCipher(SshContext sshContext) {
        return new SessionNullCipher(
                sshContext,
                new CipherState(
                        sshContext.getChooser().getSelectedCompressionAlgorithm(),
                        sshContext.getChooser().getSelectedEncryptionAlgorithm(),
                        sshContext.getChooser().getSelectedMacAlgorithm(),
                        sshContext.getChooser().getSelectedKeyExchangeAlgorithm(),
                        null,
                        null,
                        null));
    }

    private SessionCipherFactory() {}
}
