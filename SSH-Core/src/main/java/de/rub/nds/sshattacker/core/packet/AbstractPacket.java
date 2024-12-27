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
import de.rub.nds.sshattacker.core.packet.parser.AbstractPacketParser;
import de.rub.nds.sshattacker.core.protocol.common.ModifiableVariableHolder;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public abstract class AbstractPacket extends ModifiableVariableHolder {
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

    protected AbstractPacket() {
        super();
    }

    protected AbstractPacket(AbstractPacket other) {
        super(other);
        ciphertext = other.ciphertext != null ? other.ciphertext.createCopy() : null;
        compressedPayload =
                other.compressedPayload != null ? other.compressedPayload.createCopy() : null;
        payload = other.payload != null ? other.payload.createCopy() : null;
    }

    @Override
    public abstract AbstractPacket createCopy();

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

    public abstract void prepare(Chooser chooser);

    public abstract byte[] serialize();

    public abstract AbstractPacketParser<? extends AbstractPacket> getPacketParser(
            byte[] array, int startPosition, PacketCipher activeDecryptCipher, int sequenceNumber);

    public abstract void prepareComputations();
}
