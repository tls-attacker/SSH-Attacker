/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.packet.cipher;

import de.rub.nds.sshattacker.core.constants.EncryptionAlgorithm;
import de.rub.nds.sshattacker.core.constants.EncryptionMode;
import de.rub.nds.sshattacker.core.constants.MacAlgorithm;
import de.rub.nds.sshattacker.core.packet.cipher.keys.KeySet;
import de.rub.nds.sshattacker.core.state.SshContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PacketCipherFactory {

    private static final Logger LOGGER = LogManager.getLogger();

    public static PacketCipher getPacketCipher(
            SshContext context,
            KeySet keySet,
            EncryptionAlgorithm encryptionAlgorithm,
            MacAlgorithm macAlgorithm) {
        try {
            if (encryptionAlgorithm == EncryptionAlgorithm.CHACHA20_POLY1305_OPENSSH_COM) {
                return new PacketChaCha20Poly1305Cipher(context, keySet);
            } else if (encryptionAlgorithm.getMode() == EncryptionMode.GCM) {
                return new PacketGCMCipher(context, keySet, encryptionAlgorithm);
            } else {
                return new PacketMacedCipher(context, keySet, encryptionAlgorithm, macAlgorithm);
            }
        } catch (Exception e) {
            LOGGER.debug(
                    "Could not PacketCipher from the current context! Creating none Cipher", e);
            return getNoneCipher(context);
        }
    }

    public static PacketCipher getNoneCipher(SshContext context) {
        return new PacketMacedCipher(context, null, EncryptionAlgorithm.NONE, MacAlgorithm.NONE);
    }
}
