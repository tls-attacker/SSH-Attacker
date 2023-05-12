/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.packet.crypto;

import de.rub.nds.sshattacker.core.packet.cipher.PacketCipher;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.ArrayList;

@SuppressWarnings("AbstractClassWithoutAbstractMethods")
public abstract class PacketCryptoUnit {

    private static final Logger LOGGER = LogManager.getLogger();

    private final ArrayList<PacketCipher> packetCipherList;

    PacketCryptoUnit(PacketCipher packetCipher) {
        super();
        packetCipherList = new ArrayList<>();
        packetCipherList.add(0, packetCipher);
    }

    public PacketCipher getPacketMostRecentCipher() {
        return packetCipherList.get(packetCipherList.size() - 1);
    }

    public PacketCipher getPacketCipher(int epoch) {
        if (packetCipherList.size() > epoch) {
            return packetCipherList.get(epoch);
        } else {
            LOGGER.warn("Got no PacketCipher for epoch: {} using epoch 0 cipher", epoch);
            return packetCipherList.get(0);
        }
    }

    public void addNewPacketCipher(PacketCipher packetCipher) {
        packetCipherList.add(packetCipher);
    }

    public void removeAllCiphers() {
        packetCipherList.clear();
    }

    public void removeCiphers(int toRemove) {
        while (toRemove > 0 && !packetCipherList.isEmpty()) {
            packetCipherList.remove(packetCipherList.size() - 1);
            toRemove--;
        }
        if (toRemove > 0) {
            LOGGER.warn("Could not remove as many ciphers as specified");
        }
    }
}
