/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.packet.cipher;

import de.rub.nds.sshattacker.core.constants.EncryptionAlgorithm;
import de.rub.nds.sshattacker.core.constants.EncryptionAlgorithmType;
import de.rub.nds.sshattacker.core.constants.MacAlgorithm;
import de.rub.nds.sshattacker.core.crypto.packet.keys.KeySet;
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
            if (encryptionAlgorithm.getType() == EncryptionAlgorithmType.BLOCK) {
                return new PacketBlockCipher(context, keySet, encryptionAlgorithm, macAlgorithm);
            } else if (encryptionAlgorithm.getType() == EncryptionAlgorithmType.AEAD) {
                return new PacketAEADCipher(context, keySet, encryptionAlgorithm);
            } else if (encryptionAlgorithm == EncryptionAlgorithm.NONE) {
                return getNoneCipher(context);
            }
            LOGGER.warn("Unsupported cipher type: " + encryptionAlgorithm.getType());
            return getNoneCipher(context);
        } catch (Exception e) {
            LOGGER.debug(
                    "Could not PacketCipher from the current context! Creating none Cipher", e);
            return getNoneCipher(context);
        }
    }

    public static PacketNoneCipher getNoneCipher(SshContext context) {
        return new PacketNoneCipher(context, EncryptionAlgorithm.NONE, MacAlgorithm.NONE);
    }
}
