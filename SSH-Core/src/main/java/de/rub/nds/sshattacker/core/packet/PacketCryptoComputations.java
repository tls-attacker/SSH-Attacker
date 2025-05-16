/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.packet;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.ModifiableVariableHolder;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.sshattacker.core.constants.BinaryPacketField;
import java.util.Objects;
import java.util.Set;

public class PacketCryptoComputations extends ModifiableVariableHolder {

    /** The key used for the symmetric cipher */
    private ModifiableByteArray encryptionKey;

    /** The key used for the MAC */
    private ModifiableByteArray integrityKey;

    /** Set to true whenever the plainPacketBytes field only contains the first decrypted block */
    private boolean plainPacketBytesFirstBlockOnly;

    /**
     * The bytes which are going to be passed to the encrypt function. If encrypt-and-mac is used,
     * this field will be used to store the early decryption of the first block until the entire
     * packet has been decrypted. In this case, the modifiable variable is accessed using the
     * getOriginalValue() to avoid modification prior to full packet decryption.
     */
    private ModifiableByteArray plainPacketBytes;

    /** The bytes which are going to be passed to the MAC function */
    private ModifiableByteArray authenticatedPacketBytes;

    /** Only used with AEAD ciphers - contains the AAD of this packet */
    private ModifiableByteArray additionalAuthenticatedData;

    /** The initialization vector used for encryption and decryption of this packet */
    private ModifiableByteArray iv;

    /** The set of binary packet fields covered by the encryption */
    private Set<BinaryPacketField> encryptedPacketFields;

    /** A flag indicating whether the padding is considered valid */
    private Boolean paddingValid;

    /** A flag indicating whether the mac is considered valid */
    private Boolean macValid;

    @Override
    public void reset() {
        super.reset();
        encryptedPacketFields.clear();
        plainPacketBytesFirstBlockOnly = false;
        paddingValid = null;
        macValid = null;
    }

    public ModifiableByteArray getEncryptionKey() {
        return encryptionKey;
    }

    public void setEncryptionKey(ModifiableByteArray encryptionKey) {
        this.encryptionKey = encryptionKey;
    }

    public void setEncryptionKey(byte[] encryptionKey) {
        this.encryptionKey =
                ModifiableVariableFactory.safelySetValue(this.encryptionKey, encryptionKey);
    }

    public ModifiableByteArray getIntegrityKey() {
        return integrityKey;
    }

    public void setIntegrityKey(ModifiableByteArray integrityKey) {
        this.integrityKey = integrityKey;
    }

    public void setIntegrityKey(byte[] macKey) {
        integrityKey = ModifiableVariableFactory.safelySetValue(integrityKey, macKey);
    }

    public boolean isPlainPacketBytesFirstBlockOnly() {
        return plainPacketBytesFirstBlockOnly;
    }

    public ModifiableByteArray getPlainPacketBytes() {
        return plainPacketBytes;
    }

    public void setPlainPacketBytes(ModifiableByteArray plainPacketBytes) {
        setPlainPacketBytes(plainPacketBytes, false);
    }

    public void setPlainPacketBytes(ModifiableByteArray plainPacketBytes, boolean firstBlockOnly) {
        this.plainPacketBytes = plainPacketBytes;
        plainPacketBytesFirstBlockOnly = firstBlockOnly;
    }

    public void setPlainPacketBytes(byte[] plainPacketBytes) {
        setPlainPacketBytes(plainPacketBytes, false);
    }

    public void setPlainPacketBytes(byte[] plainPacketBytes, boolean firstBlockOnly) {
        this.plainPacketBytes =
                ModifiableVariableFactory.safelySetValue(this.plainPacketBytes, plainPacketBytes);
        plainPacketBytesFirstBlockOnly = firstBlockOnly;
    }

    public ModifiableByteArray getAuthenticatedPacketBytes() {
        return authenticatedPacketBytes;
    }

    public void setAuthenticatedPacketBytes(ModifiableByteArray authenticatedPacketBytes) {
        this.authenticatedPacketBytes = authenticatedPacketBytes;
    }

    public void setAuthenticatedPacketBytes(byte[] authenticatedPacketBytes) {
        this.authenticatedPacketBytes =
                ModifiableVariableFactory.safelySetValue(
                        this.authenticatedPacketBytes, authenticatedPacketBytes);
    }

    public ModifiableByteArray getAdditionalAuthenticatedData() {
        return additionalAuthenticatedData;
    }

    public void setAdditionalAuthenticatedData(ModifiableByteArray additionalAuthenticatedData) {
        this.additionalAuthenticatedData = additionalAuthenticatedData;
    }

    public void setAdditionalAuthenticatedData(byte[] additionalAuthenticatedData) {
        this.additionalAuthenticatedData =
                ModifiableVariableFactory.safelySetValue(
                        this.additionalAuthenticatedData, additionalAuthenticatedData);
    }

    public ModifiableByteArray getIv() {
        return iv;
    }

    public void setIv(ModifiableByteArray iv) {
        this.iv = iv;
    }

    public void setIv(byte[] iv) {
        this.iv = ModifiableVariableFactory.safelySetValue(this.iv, iv);
    }

    public Set<BinaryPacketField> getEncryptedPacketFields() {
        return encryptedPacketFields;
    }

    public void setEncryptedPacketFields(Set<BinaryPacketField> encryptedPacketFields) {
        this.encryptedPacketFields = encryptedPacketFields;
    }

    public Boolean getPaddingValid() {
        return paddingValid;
    }

    public void setPaddingValid(boolean paddingValid) {
        this.paddingValid = paddingValid;
    }

    public Boolean getMacValid() {
        return macValid;
    }

    public void setMacValid(boolean macValid) {
        this.macValid = macValid;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        PacketCryptoComputations that = (PacketCryptoComputations) obj;
        return Objects.equals(encryptionKey, that.encryptionKey)
                && Objects.equals(integrityKey, that.integrityKey)
                && Objects.equals(
                        plainPacketBytesFirstBlockOnly, that.plainPacketBytesFirstBlockOnly)
                && Objects.equals(plainPacketBytes, that.plainPacketBytes)
                && Objects.equals(authenticatedPacketBytes, that.authenticatedPacketBytes)
                && Objects.equals(encryptedPacketFields, that.encryptedPacketFields)
                && Objects.equals(paddingValid, that.paddingValid)
                && Objects.equals(macValid, that.macValid);
    }

    @Override
    public int hashCode() {
        return Objects.hash(
                encryptionKey,
                integrityKey,
                plainPacketBytesFirstBlockOnly,
                plainPacketBytes,
                authenticatedPacketBytes,
                encryptedPacketFields,
                paddingValid,
                macValid);
    }
}
