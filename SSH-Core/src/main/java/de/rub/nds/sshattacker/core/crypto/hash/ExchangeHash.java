/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.hash;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.exceptions.AdjustmentException;
import de.rub.nds.sshattacker.core.protocol.transport.message.KeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.protocol.transport.message.VersionExchangeMessage;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.KeyExchangeInitMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ExchangeHash {

    private static final Logger LOGGER = LogManager.getLogger();

    protected final SshContext context;

    protected String clientVersion;
    protected String serverVersion;
    protected byte[] clientKeyExchangeInit;
    protected byte[] serverKeyExchangeInit;
    protected byte[] serverHostKey;
    protected byte[] sharedSecret;

    protected byte[] hash;

    public ExchangeHash(SshContext context) {
        this.context = context;
    }

    public SshContext getContext() {
        return context;
    }

    public String getClientVersion() {
        return clientVersion;
    }

    public void setClientVersion(String clientVersion) {
        this.clientVersion = clientVersion;
    }

    public void setClientVersion(VersionExchangeMessage clientVersion) {
        this.clientVersion = clientVersion.getIdentification();
    }

    public String getServerVersion() {
        return serverVersion;
    }

    public void setServerVersion(String serverVersion) {
        this.serverVersion = serverVersion;
    }

    public void setServerVersion(VersionExchangeMessage serverVersion) {
        this.serverVersion = serverVersion.getIdentification();
    }

    public byte[] getClientKeyExchangeInit() {
        return clientKeyExchangeInit;
    }

    public void setClientKeyExchangeInit(byte[] clientKeyExchangeInit) {
        this.clientKeyExchangeInit = clientKeyExchangeInit;
    }

    public void setClientKeyExchangeInit(KeyExchangeInitMessage clientKeyExchangeInit) {
        this.clientKeyExchangeInit =
                new KeyExchangeInitMessageSerializer(clientKeyExchangeInit).serialize();
    }

    public byte[] getServerKeyExchangeInit() {
        return serverKeyExchangeInit;
    }

    public void setServerKeyExchangeInit(byte[] serverKeyExchangeInit) {
        this.serverKeyExchangeInit = serverKeyExchangeInit;
    }

    public void setServerKeyExchangeInit(KeyExchangeInitMessage serverKeyExchangeInit) {
        this.serverKeyExchangeInit =
                new KeyExchangeInitMessageSerializer(serverKeyExchangeInit).serialize();
    }

    public byte[] getServerHostKey() {
        return serverHostKey;
    }

    public void setServerHostKey(byte[] serverHostKey) {
        this.serverHostKey = serverHostKey;
    }

    public byte[] getSharedSecret() {
        return sharedSecret;
    }

    public void setSharedSecret(byte[] sharedSecret) {
        this.sharedSecret = sharedSecret;
    }

    public void setSharedSecret(BigInteger sharedSecret) {
        this.sharedSecret = sharedSecret.toByteArray();
    }

    protected boolean areRequiredInputsMissing() {
        return clientVersion == null
                || serverVersion == null
                || clientKeyExchangeInit == null
                || serverKeyExchangeInit == null
                || serverHostKey == null
                || sharedSecret == null;
    }

    protected void compute() {
        byte[] input = getHashInput();
        LOGGER.debug("Exchange hash input: " + ArrayConverter.bytesToRawHexString(input));
        MessageDigest md;
        try {
            md =
                    MessageDigest.getInstance(
                            context.getKeyExchangeAlgorithm()
                                    .orElseThrow(AdjustmentException::new)
                                    .getDigest());
        } catch (NoSuchAlgorithmException e) {
            LOGGER.error(
                    "Provider does not support this hash function: "
                            + context.getKeyExchangeAlgorithm().get().getDigest(),
                    e);
            throw new AdjustmentException(
                    "Unable to calculate exchange hash due to unsupported hash algorithm.", e);
        }
        hash = md.digest(input);
        LOGGER.info("Computed exchange hash: " + ArrayConverter.bytesToRawHexString(hash));
    }

    protected byte[] getHashInput() {
        throw new AdjustmentException(
                "Tried to call ExchangeHash::getHashInput on the base class. Instantiate a new ExchangeHash subclass first.");
    }

    public boolean isReady() {
        return hash != null;
    }

    public byte[] get() {
        if (!isReady()) {
            if (areRequiredInputsMissing()) {
                throw new AdjustmentException(
                        "Unable to retrieve exchange hash, exchange hash is not ready");
            }
            compute();
        }
        return hash;
    }
}
