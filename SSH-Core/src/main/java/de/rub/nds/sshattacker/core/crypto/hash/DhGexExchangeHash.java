/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.hash;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.crypto.keys.CustomDhPublicKey;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DhGexExchangeHash extends ExchangeHash {

    private static final Logger LOGGER = LogManager.getLogger();

    private Integer minimalGroupSize;
    private Integer preferredGroupSize;
    private Integer maximalGroupSize;
    private byte[] groupModulus;
    private byte[] groupGenerator;

    private byte[] clientDHPublicKey;
    private byte[] serverDHPublicKey;

    public DhGexExchangeHash(SshContext context) {
        super(context);
    }

    public Integer getMinimalGroupSize() {
        return minimalGroupSize;
    }

    public void setMinimalGroupSize(int minimalGroupSize) {
        this.minimalGroupSize = minimalGroupSize;
    }

    public Integer getPreferredGroupSize() {
        return preferredGroupSize;
    }

    public void setPreferredGroupSize(int preferredGroupSize) {
        this.preferredGroupSize = preferredGroupSize;
    }

    public Integer getMaximalGroupSize() {
        return maximalGroupSize;
    }

    public void setMaximalGroupSize(int maximalGroupSize) {
        this.maximalGroupSize = maximalGroupSize;
    }

    public byte[] getGroupGenerator() {
        return groupGenerator;
    }

    public void setGroupGenerator(byte[] groupGenerator) {
        this.groupGenerator = groupGenerator;
    }

    public void setGroupGenerator(BigInteger groupGenerator) {
        this.groupGenerator = groupGenerator.toByteArray();
    }

    public byte[] getGroupModulus() {
        return groupModulus;
    }

    public void setGroupModulus(byte[] groupModulus) {
        this.groupModulus = groupModulus;
    }

    public void setGroupModulus(BigInteger groupModulus) {
        this.groupModulus = groupModulus.toByteArray();
    }

    public byte[] getClientDHPublicKey() {
        return clientDHPublicKey;
    }

    public void setClientDHPublicKey(byte[] clientDHPublicKey) {
        this.clientDHPublicKey = clientDHPublicKey;
    }

    public void setClientDHPublicKey(BigInteger clientDHPublicKey) {
        this.clientDHPublicKey = clientDHPublicKey.toByteArray();
    }

    public void setClientDHPublicKey(CustomDhPublicKey clientDHPublicKey) {
        this.clientDHPublicKey = clientDHPublicKey.getY().toByteArray();
    }

    public byte[] getServerDHPublicKey() {
        return serverDHPublicKey;
    }

    public void setServerDHPublicKey(byte[] serverDHPublicKey) {
        this.serverDHPublicKey = serverDHPublicKey;
    }

    public void setServerDHPublicKey(BigInteger serverDHPublicKey) {
        this.serverDHPublicKey = serverDHPublicKey.toByteArray();
    }

    public void setServerDHPublicKey(CustomDhPublicKey serverDHPublicKey) {
        this.serverDHPublicKey = serverDHPublicKey.getY().toByteArray();
    }

    @Override
    protected boolean areRequiredInputsMissing() {
        return super.areRequiredInputsMissing()
                || minimalGroupSize == null
                || preferredGroupSize == null
                || maximalGroupSize == null
                || groupModulus == null
                || groupGenerator == null
                || clientDHPublicKey == null
                || serverDHPublicKey == null;
    }

    @Override
    protected byte[] getHashInput() {
        return ArrayConverter.concatenate(
                Converter.stringToLengthPrefixedBinaryString(clientVersion),
                Converter.stringToLengthPrefixedBinaryString(serverVersion),
                Converter.bytesToLengthPrefixedBinaryString(clientKeyExchangeInit),
                Converter.bytesToLengthPrefixedBinaryString(serverKeyExchangeInit),
                Converter.bytesToLengthPrefixedBinaryString(serverHostKey),
                ArrayConverter.intToBytes(minimalGroupSize, DataFormatConstants.INT32_SIZE),
                ArrayConverter.intToBytes(preferredGroupSize, DataFormatConstants.INT32_SIZE),
                ArrayConverter.intToBytes(maximalGroupSize, DataFormatConstants.INT32_SIZE),
                Converter.byteArrayToMpint(groupModulus),
                Converter.byteArrayToMpint(groupGenerator),
                Converter.byteArrayToMpint(clientDHPublicKey),
                Converter.byteArrayToMpint(serverDHPublicKey),
                Converter.byteArrayToMpint(sharedSecret));
    }

    public static DhGexExchangeHash from(ExchangeHash exchangeHash) {
        DhGexExchangeHash dhGexExchangeHash = new DhGexExchangeHash(exchangeHash.context);
        dhGexExchangeHash.setClientVersion(exchangeHash.clientVersion);
        dhGexExchangeHash.setServerVersion(exchangeHash.serverVersion);
        dhGexExchangeHash.setClientKeyExchangeInit(exchangeHash.clientKeyExchangeInit);
        dhGexExchangeHash.setServerKeyExchangeInit(exchangeHash.serverKeyExchangeInit);
        dhGexExchangeHash.setServerHostKey(exchangeHash.serverHostKey);
        dhGexExchangeHash.setSharedSecret(exchangeHash.sharedSecret);
        if (exchangeHash instanceof DhGexExchangeHash) {
            dhGexExchangeHash.setMinimalGroupSize(
                    ((DhGexExchangeHash) exchangeHash).minimalGroupSize);
            dhGexExchangeHash.setPreferredGroupSize(
                    ((DhGexExchangeHash) exchangeHash).preferredGroupSize);
            dhGexExchangeHash.setMaximalGroupSize(
                    ((DhGexExchangeHash) exchangeHash).maximalGroupSize);
            dhGexExchangeHash.setGroupModulus(((DhGexExchangeHash) exchangeHash).groupModulus);
            dhGexExchangeHash.setGroupGenerator(((DhGexExchangeHash) exchangeHash).groupGenerator);
            dhGexExchangeHash.setClientDHPublicKey(
                    ((DhGexExchangeHash) exchangeHash).clientDHPublicKey);
            dhGexExchangeHash.setServerDHPublicKey(
                    ((DhGexExchangeHash) exchangeHash).serverDHPublicKey);
        } else if (exchangeHash instanceof DhGexOldExchangeHash) {
            dhGexExchangeHash.setPreferredGroupSize(
                    ((DhGexOldExchangeHash) exchangeHash).getPreferredGroupSize());
            dhGexExchangeHash.setGroupModulus(
                    ((DhGexOldExchangeHash) exchangeHash).getGroupModulus());
            dhGexExchangeHash.setGroupGenerator(
                    ((DhGexOldExchangeHash) exchangeHash).getGroupGenerator());
            dhGexExchangeHash.setClientDHPublicKey(
                    ((DhGexOldExchangeHash) exchangeHash).getClientDHPublicKey());
            dhGexExchangeHash.setServerDHPublicKey(
                    ((DhGexOldExchangeHash) exchangeHash).getServerDHPublicKey());
        }
        return dhGexExchangeHash;
    }
}
