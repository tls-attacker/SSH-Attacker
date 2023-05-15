/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.packet;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableProperty;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.sshattacker.core.packet.cipher.PacketCipher;
import de.rub.nds.sshattacker.core.packet.compressor.PacketCompressor;
import de.rub.nds.sshattacker.core.packet.crypto.AbstractPacketEncryptor;
import de.rub.nds.sshattacker.core.packet.parser.AbstractPacketParser;
import de.rub.nds.sshattacker.core.packet.preparator.AbstractPacketPreparator;
import de.rub.nds.sshattacker.core.packet.serializer.AbstractPacketSerializer;
import de.rub.nds.sshattacker.core.protocol.common.ModifiableVariableHolder;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public abstract class AbstractPacket extends ModifiableVariableHolder {

    /**
     * This field contains the packet bytes sent over the network. This includes packet_length,
     * padding_length, payload, padding and mac (some fields may be encrypted).
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.CIPHERTEXT)
    private ModifiableByteArray completePacketBytes;

    /**
     * The encrypted contents of the packet. If no encryption (NONE) is used, this field contains
     * the unencrypted payload.
     */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.CIPHERTEXT)
    private ModifiableByteArray ciphertext;

    /** The compressed payload of this packet. */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PLAIN_PROTOCOL_MESSAGE)
    private ModifiableByteArray compressedPayload;

    /** The useful contents of the packet. */
    @ModifiableVariableProperty(type = ModifiableVariableProperty.Type.PLAIN_PROTOCOL_MESSAGE)
    private ModifiableByteArray payload;

    public ModifiableByteArray getCompletePacketBytes() {
        return completePacketBytes;
    }

    public void setCompletePacketBytes(ModifiableByteArray completePacketBytes) {
        this.completePacketBytes = completePacketBytes;
    }

    public void setCompletePacketBytes(byte[] completePacketBytes) {
        this.completePacketBytes =
                ModifiableVariableFactory.safelySetValue(
                        this.completePacketBytes, completePacketBytes);
    }

    public ModifiableByteArray getCiphertext() {
        return ciphertext;
    }

    public void setCiphertext(ModifiableByteArray ciphertext) {
        this.ciphertext = ciphertext;
    }

    public void setCiphertext(byte[] ciphertext) {
        this.ciphertext = ModifiableVariableFactory.safelySetValue(this.ciphertext, ciphertext);
    }

    public ModifiableByteArray getCompressedPayload() {
        return compressedPayload;
    }

    public void setCompressedPayload(ModifiableByteArray compressedPayload) {
        this.compressedPayload = compressedPayload;
    }

    public void setCompressedPayload(byte[] compressedPayload) {
        this.compressedPayload =
                ModifiableVariableFactory.safelySetValue(this.compressedPayload, compressedPayload);
    }

    public ModifiableByteArray getPayload() {
        return payload;
    }

    public void setPayload(ModifiableByteArray payload) {
        this.payload = payload;
    }

    public void setPayload(byte[] payload) {
        this.payload = ModifiableVariableFactory.safelySetValue(this.payload, payload);
    }

    public abstract AbstractPacketPreparator<? extends AbstractPacket> getPacketPreparator(
            Chooser chooser, AbstractPacketEncryptor encryptor, PacketCompressor compressor);

    public abstract AbstractPacketParser<? extends AbstractPacket> getPacketParser(
            byte[] array, int startPosition, PacketCipher activeDecryptCipher, int sequenceNumber);

    public abstract AbstractPacketSerializer<? extends AbstractPacket> getPacketSerializer();

    public abstract void prepareComputations();
}
