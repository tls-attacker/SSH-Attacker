/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.packet;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.sshattacker.core.constants.BinaryPacketField;
import de.rub.nds.sshattacker.core.protocol.common.ModifiableVariableHolder;
import java.util.Objects;
import java.util.Set;

public class PacketCryptoComputations extends ModifiableVariableHolder {

    /** The key used for the symmetric cipher */
    private ModifiableByteArray encryptionKey;

    /** The key used for the MAC */
    private ModifiableByteArray integrityKey;

    /** The MAC / authentication tag value of the packet */
    private ModifiableByteArray mac;

    /** The length of the padding */
    private ModifiableByte paddingLength;

    /** The whole padding */
    private ModifiableByteArray padding;

    /** Set to true whenever the plainPacketBytes field only contains the first decrypted block */
    private boolean plainPacketBytesFirstBlockOnly = false;

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

    /** The pure ciphertext part of the packet. The output from the negotiated cipher */
    private ModifiableByteArray ciphertext;

    /** The set of binary packet fields covered by the encryption */
    private Set<BinaryPacketField> encryptedPacketFields;

    /** The authentication tag of the packet if using GCM cipher suites */
    private ModifiableByteArray authenticationTag;

    private Boolean paddingValid = null;

    private Boolean macValid = null;

    private Boolean authenticationTagValid = null;

    public PacketCryptoComputations() {}

    @Override
    public void reset() {
        super.reset();
        encryptedPacketFields.clear();
        plainPacketBytesFirstBlockOnly = false;
        paddingValid = null;
        macValid = null;
        authenticationTagValid = null;
    }

    public ModifiableByteArray getEncryptionKey() {
        return encryptionKey;
    }

    public void setEncryptionKey(ModifiableByteArray encryptionKey) {
        this.encryptionKey = encryptionKey;
    }

    public void setEncryptionKey(byte[] cipherKey) {
        this.encryptionKey =
                ModifiableVariableFactory.safelySetValue(this.encryptionKey, cipherKey);
    }

    public ModifiableByteArray getIntegrityKey() {
        return integrityKey;
    }

    public void setIntegrityKey(ModifiableByteArray integrityKey) {
        this.integrityKey = integrityKey;
    }

    public void setIntegrityKey(byte[] macKey) {
        this.integrityKey = ModifiableVariableFactory.safelySetValue(this.integrityKey, macKey);
    }

    public ModifiableByteArray getMac() {
        return mac;
    }

    public void setMac(ModifiableByteArray mac) {
        this.mac = mac;
    }

    public void setMac(byte[] mac) {
        this.mac = ModifiableVariableFactory.safelySetValue(this.mac, mac);
    }

    public ModifiableByte getPaddingLength() {
        return paddingLength;
    }

    public void setPaddingLength(ModifiableByte paddingLength) {
        this.paddingLength = paddingLength;
    }

    public void setPaddingLength(byte paddingLength) {
        this.paddingLength =
                ModifiableVariableFactory.safelySetValue(this.paddingLength, paddingLength);
    }

    public ModifiableByteArray getPadding() {
        return padding;
    }

    public void setPadding(ModifiableByteArray padding) {
        this.padding = padding;
    }

    public void setPadding(byte[] padding) {
        this.padding = ModifiableVariableFactory.safelySetValue(this.padding, padding);
    }

    public boolean isPlainPacketBytesFirstBlockOnly() {
        return plainPacketBytesFirstBlockOnly;
    }

    public void setPlainPacketBytesFirstBlockOnly(boolean plainPacketBytesFirstBlockOnly) {
        this.plainPacketBytesFirstBlockOnly = plainPacketBytesFirstBlockOnly;
    }

    public ModifiableByteArray getPlainPacketBytes() {
        return plainPacketBytes;
    }

    public void setPlainPacketBytes(ModifiableByteArray plainPacketBytes) {
        this.plainPacketBytes = plainPacketBytes;
    }

    public void setPlainPacketBytes(byte[] plainPacketBytes) {
        this.plainPacketBytes =
                ModifiableVariableFactory.safelySetValue(this.plainPacketBytes, plainPacketBytes);
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

    public ModifiableByteArray getIV() {
        return iv;
    }

    public void setIV(ModifiableByteArray iv) {
        this.iv = iv;
    }

    public void setIV(byte[] iv) {
        this.iv = ModifiableVariableFactory.safelySetValue(this.iv, iv);
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

    public Set<BinaryPacketField> getEncryptedPacketFields() {
        return encryptedPacketFields;
    }

    public void setEncryptedPacketFields(Set<BinaryPacketField> encryptedPacketFields) {
        this.encryptedPacketFields = encryptedPacketFields;
    }

    public ModifiableByteArray getAuthenticationTag() {
        return authenticationTag;
    }

    public void setAuthenticationTag(ModifiableByteArray authenticationTag) {
        this.authenticationTag = authenticationTag;
    }

    public void setAuthenticationTag(byte[] authenticationTag) {
        this.authenticationTag =
                ModifiableVariableFactory.safelySetValue(this.authenticationTag, authenticationTag);
    }

    public Boolean getPaddingValid() {
        return paddingValid;
    }

    public void setPaddingValid(Boolean paddingValid) {
        this.paddingValid = paddingValid;
    }

    public Boolean getMacValid() {
        return macValid;
    }

    public void setMacValid(Boolean macValid) {
        this.macValid = macValid;
    }

    public Boolean getAuthenticationTagValid() {
        return authenticationTagValid;
    }

    public void setAuthenticationTagValid(Boolean authenticationTagValid) {
        this.authenticationTagValid = authenticationTagValid;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PacketCryptoComputations that = (PacketCryptoComputations) o;
        return Objects.equals(encryptionKey, that.encryptionKey)
                && Objects.equals(integrityKey, that.integrityKey)
                && Objects.equals(mac, that.mac)
                && Objects.equals(paddingLength, that.paddingLength)
                && Objects.equals(padding, that.padding)
                && Objects.equals(
                        plainPacketBytesFirstBlockOnly, that.plainPacketBytesFirstBlockOnly)
                && Objects.equals(plainPacketBytes, that.plainPacketBytes)
                && Objects.equals(authenticatedPacketBytes, that.authenticatedPacketBytes)
                && Objects.equals(ciphertext, that.ciphertext)
                && Objects.equals(encryptedPacketFields, that.encryptedPacketFields)
                && Objects.equals(authenticationTag, that.authenticationTag)
                && Objects.equals(paddingValid, that.paddingValid)
                && Objects.equals(macValid, that.macValid)
                && Objects.equals(authenticationTagValid, that.authenticationTagValid);
    }

    @Override
    public int hashCode() {
        return Objects.hash(
                encryptionKey,
                integrityKey,
                mac,
                paddingLength,
                padding,
                plainPacketBytesFirstBlockOnly,
                plainPacketBytes,
                authenticatedPacketBytes,
                ciphertext,
                encryptedPacketFields,
                authenticationTag,
                paddingValid,
                macValid,
                authenticationTagValid);
    }
}
