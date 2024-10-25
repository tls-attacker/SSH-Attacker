/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.packet.cipher;

import de.rub.nds.sshattacker.core.constants.CipherMode;
import de.rub.nds.sshattacker.core.constants.EncryptionAlgorithm;
import de.rub.nds.sshattacker.core.constants.EncryptionMode;
import de.rub.nds.sshattacker.core.constants.MacAlgorithm;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.packet.cipher.keys.AbstractKeySet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public final class PacketCipherFactory {

    private static final Logger LOGGER = LogManager.getLogger();

    private PacketCipherFactory() {
        super();
    }

    public static PacketCipher getPacketCipher(
            SshContext context,
            AbstractKeySet keySet,
            EncryptionAlgorithm encryptionAlgorithm,
            MacAlgorithm macAlgorithm,
            CipherMode mode) {
        try {
            if (encryptionAlgorithm == EncryptionAlgorithm.CHACHA20_POLY1305_OPENSSH_COM) {
                return new PacketChaCha20Poly1305Cipher(context, keySet, mode);
            } else if (encryptionAlgorithm.getMode() == EncryptionMode.GCM) {
                return new PacketGCMCipher(context, keySet, encryptionAlgorithm, mode);
            } else if (encryptionAlgorithm == EncryptionAlgorithm.BLOWFISH_CBC) {
                return new PacketSsh1Cipher(
                        context, keySet, EncryptionAlgorithm.BLOWFISH_CBC, null, mode);
            } else if (encryptionAlgorithm == EncryptionAlgorithm.TRIPLE_DES_CBC) {
                return new PacketSsh1Cipher(
                        context, keySet, EncryptionAlgorithm.TRIPLE_DES_CBC, null, mode);
            } else if (encryptionAlgorithm == EncryptionAlgorithm.NONE && macAlgorithm == null) {
                return getNoneCipher(context, mode);
            } else {
                return new PacketMacedCipher(
                        context, keySet, encryptionAlgorithm, macAlgorithm, mode);
            }
        } catch (Exception e) {
            LOGGER.warn(
                    "Could not create PacketCipher with encryption algorithm '{}' and MAC algorithm '{}'! Creating 'none' Cipher instead",
                    encryptionAlgorithm,
                    macAlgorithm,
                    e);
            return getNoneCipher(context, mode);
        }
    }

    public static PacketCipher getNoneCipher(SshContext context, CipherMode mode) {
        return new PacketMacedCipher(
                context, null, EncryptionAlgorithm.NONE, MacAlgorithm.NONE, mode);
    }
}
