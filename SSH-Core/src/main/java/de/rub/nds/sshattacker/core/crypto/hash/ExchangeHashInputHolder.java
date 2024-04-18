/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.hash;

import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPublicKey;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.protocol.transport.message.KeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.protocol.transport.message.VersionExchangeMessage;
import java.math.BigInteger;
import java.util.Optional;

/** A holder class to store all required values for exchange hash computation. */
public final class ExchangeHashInputHolder {

    // region General exchange hash fields
    private VersionExchangeMessage clientVersion;
    private VersionExchangeMessage serverVersion;
    private KeyExchangeInitMessage clientKeyExchangeInit;
    private KeyExchangeInitMessage serverKeyExchangeInit;
    private SshPublicKey<?, ?> serverHostKey;
    private byte[] sharedSecret;
    // endregion

    // region Named DH exchange hash fields
    private BigInteger dhClientPublicKey;
    private BigInteger dhServerPublicKey;
    // endregion

    // region DH GEX (group exchange) exchange hash fields
    private Integer dhGexMinimalGroupSize;
    private Integer dhGexPreferredGroupSize;
    private Integer dhGexMaximalGroupSize;
    private BigInteger dhGexGroupModulus;
    private BigInteger dhGexGroupGenerator;
    private BigInteger dhGexClientPublicKey;
    private BigInteger dhGexServerPublicKey;
    // endregion

    // region ECDH exchange hash fields
    private byte[] ecdhClientPublicKey;
    private byte[] ecdhServerPublicKey;
    // endregion

    // region hybrid exchange hash fields
    private byte[] hybridClientPublicKey;
    private byte[] hybridServerPublicKey;

    // region RSA exchange hash fields
    private SshPublicKey<CustomRsaPublicKey, ?> rsaTransientKey;
    private byte[] rsaEncryptedSecret;

    // endregion

    // region Getters / setters general exchange hash fields
    public Optional<VersionExchangeMessage> getClientVersion() {
        return Optional.ofNullable(clientVersion);
    }

    public void setClientVersion(VersionExchangeMessage clientVersion) {
        this.clientVersion = clientVersion;
    }

    public Optional<VersionExchangeMessage> getServerVersion() {
        return Optional.ofNullable(serverVersion);
    }

    public void setServerVersion(VersionExchangeMessage serverVersion) {
        this.serverVersion = serverVersion;
    }

    public Optional<KeyExchangeInitMessage> getClientKeyExchangeInit() {
        return Optional.ofNullable(clientKeyExchangeInit);
    }

    public void setClientKeyExchangeInit(KeyExchangeInitMessage clientKeyExchangeInit) {
        this.clientKeyExchangeInit = clientKeyExchangeInit;
    }

    public Optional<KeyExchangeInitMessage> getServerKeyExchangeInit() {
        return Optional.ofNullable(serverKeyExchangeInit);
    }

    public void setServerKeyExchangeInit(KeyExchangeInitMessage serverKeyExchangeInit) {
        this.serverKeyExchangeInit = serverKeyExchangeInit;
    }

    public Optional<SshPublicKey<?, ?>> getServerHostKey() {
        return Optional.ofNullable(serverHostKey);
    }

    public void setServerHostKey(SshPublicKey<?, ?> serverHostKey) {
        this.serverHostKey = serverHostKey;
    }

    public Optional<byte[]> getSharedSecret() {
        return Optional.ofNullable(sharedSecret);
    }

    public void setSharedSecret(byte[] sharedSecret) {
        this.sharedSecret = sharedSecret;
    }

    // endregion

    // region Getters / setters named DH exchange hash fields
    public Optional<BigInteger> getDhClientPublicKey() {
        return Optional.ofNullable(dhClientPublicKey);
    }

    public void setDhClientPublicKey(BigInteger dhClientPublicKey) {
        this.dhClientPublicKey = dhClientPublicKey;
    }

    public Optional<BigInteger> getDhServerPublicKey() {
        return Optional.ofNullable(dhServerPublicKey);
    }

    public void setDhServerPublicKey(BigInteger dhServerPublicKey) {
        this.dhServerPublicKey = dhServerPublicKey;
    }

    // endregion

    // region Getters / setters DH GEX exchange hash fields
    public Optional<Integer> getDhGexMinimalGroupSize() {
        return Optional.ofNullable(dhGexMinimalGroupSize);
    }

    public void setDhGexMinimalGroupSize(Integer dhGexMinimalGroupSize) {
        this.dhGexMinimalGroupSize = dhGexMinimalGroupSize;
    }

    public Optional<Integer> getDhGexPreferredGroupSize() {
        return Optional.ofNullable(dhGexPreferredGroupSize);
    }

    public void setDhGexPreferredGroupSize(Integer dhGexPreferredGroupSize) {
        this.dhGexPreferredGroupSize = dhGexPreferredGroupSize;
    }

    public Optional<Integer> getDhGexMaximalGroupSize() {
        return Optional.ofNullable(dhGexMaximalGroupSize);
    }

    public void setDhGexMaximalGroupSize(Integer dhGexMaximalGroupSize) {
        this.dhGexMaximalGroupSize = dhGexMaximalGroupSize;
    }

    public Optional<BigInteger> getDhGexGroupModulus() {
        return Optional.ofNullable(dhGexGroupModulus);
    }

    public void setDhGexGroupModulus(BigInteger dhGexGroupModulus) {
        this.dhGexGroupModulus = dhGexGroupModulus;
    }

    public Optional<BigInteger> getDhGexGroupGenerator() {
        return Optional.ofNullable(dhGexGroupGenerator);
    }

    public void setDhGexGroupGenerator(BigInteger dhGexGroupGenerator) {
        this.dhGexGroupGenerator = dhGexGroupGenerator;
    }

    public Optional<BigInteger> getDhGexClientPublicKey() {
        return Optional.ofNullable(dhGexClientPublicKey);
    }

    public void setDhGexClientPublicKey(BigInteger dhGexClientPublicKey) {
        this.dhGexClientPublicKey = dhGexClientPublicKey;
    }

    public Optional<BigInteger> getDhGexServerPublicKey() {
        return Optional.ofNullable(dhGexServerPublicKey);
    }

    public void setDhGexServerPublicKey(BigInteger dhGexServerPublicKey) {
        this.dhGexServerPublicKey = dhGexServerPublicKey;
    }

    // endregion

    // region Getters / setters ECDH exchange hash fields
    public Optional<byte[]> getEcdhClientPublicKey() {
        return Optional.ofNullable(ecdhClientPublicKey);
    }

    public void setEcdhClientPublicKey(byte[] ecdhClientPublicKey) {
        this.ecdhClientPublicKey = ecdhClientPublicKey;
    }

    public Optional<byte[]> getEcdhServerPublicKey() {
        return Optional.ofNullable(ecdhServerPublicKey);
    }

    public void setEcdhServerPublicKey(byte[] ecdhServerPublicKey) {
        this.ecdhServerPublicKey = ecdhServerPublicKey;
    }

    // endregion

    // region Getters / setters hybrid exchange hash fields
    public Optional<byte[]> getHybridClientPublicKey() {
        return Optional.ofNullable(hybridClientPublicKey);
    }

    public void setHybridClientPublicKey(byte[] hybridClientPublicKey) {
        this.hybridClientPublicKey = hybridClientPublicKey;
    }

    public Optional<byte[]> getHybridServerPublicKey() {
        return Optional.ofNullable(hybridServerPublicKey);
    }

    public void setHybridServerPublicKey(byte[] hybridServerPublicKey) {
        this.hybridServerPublicKey = hybridServerPublicKey;
    }

    // end region

    // region Getters / setters RSA exchange hash fields
    public Optional<SshPublicKey<CustomRsaPublicKey, ?>> getRsaTransientKey() {
        return Optional.ofNullable(rsaTransientKey);
    }

    public void setRsaTransientKey(SshPublicKey<CustomRsaPublicKey, ?> rsaTransientKey) {
        this.rsaTransientKey = rsaTransientKey;
    }

    public Optional<byte[]> getRsaEncryptedSecret() {
        return Optional.ofNullable(rsaEncryptedSecret);
    }

    public void setRsaEncryptedSecret(byte[] rsaEncryptedSecret) {
        this.rsaEncryptedSecret = rsaEncryptedSecret;
    }
    // endregion
}
