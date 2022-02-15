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

public class DhGexOldExchangeHash extends ExchangeHash {

    private Integer preferredGroupSize;
    private byte[] groupModulus;
    private byte[] groupGenerator;

    private byte[] clientDHPublicKey;
    private byte[] serverDHPublicKey;

    public DhGexOldExchangeHash(SshContext context) {
        super(context);
    }

    public Integer getPreferredGroupSize() {
        return preferredGroupSize;
    }

    public void setPreferredGroupSize(int preferredGroupSize) {
        this.preferredGroupSize = preferredGroupSize;
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
                || preferredGroupSize == null
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
                ArrayConverter.intToBytes(preferredGroupSize, DataFormatConstants.INT32_SIZE),
                Converter.byteArrayToMpint(groupModulus),
                Converter.byteArrayToMpint(groupGenerator),
                Converter.byteArrayToMpint(clientDHPublicKey),
                Converter.byteArrayToMpint(serverDHPublicKey),
                Converter.byteArrayToMpint(sharedSecret));
    }

    public static DhGexOldExchangeHash from(ExchangeHash exchangeHash) {
        DhGexOldExchangeHash gexDhExchangeHash = new DhGexOldExchangeHash(exchangeHash.context);
        gexDhExchangeHash.setClientVersion(exchangeHash.clientVersion);
        gexDhExchangeHash.setServerVersion(exchangeHash.serverVersion);
        gexDhExchangeHash.setClientKeyExchangeInit(exchangeHash.clientKeyExchangeInit);
        gexDhExchangeHash.setServerKeyExchangeInit(exchangeHash.serverKeyExchangeInit);
        gexDhExchangeHash.setServerHostKey(exchangeHash.serverHostKey);
        gexDhExchangeHash.setSharedSecret(exchangeHash.sharedSecret);
        if (exchangeHash instanceof DhGexOldExchangeHash) {
            gexDhExchangeHash.setPreferredGroupSize(
                    ((DhGexOldExchangeHash) exchangeHash).preferredGroupSize);
            gexDhExchangeHash.setGroupModulus(((DhGexOldExchangeHash) exchangeHash).groupModulus);
            gexDhExchangeHash.setGroupGenerator(
                    ((DhGexOldExchangeHash) exchangeHash).groupGenerator);
            gexDhExchangeHash.setClientDHPublicKey(
                    ((DhGexOldExchangeHash) exchangeHash).clientDHPublicKey);
            gexDhExchangeHash.setServerDHPublicKey(
                    ((DhGexOldExchangeHash) exchangeHash).serverDHPublicKey);
        } else if (exchangeHash instanceof DhGexExchangeHash) {
            gexDhExchangeHash.setPreferredGroupSize(
                    ((DhGexExchangeHash) exchangeHash).getPreferredGroupSize());
            gexDhExchangeHash.setGroupModulus(((DhGexExchangeHash) exchangeHash).getGroupModulus());
            gexDhExchangeHash.setGroupGenerator(
                    ((DhGexExchangeHash) exchangeHash).getGroupGenerator());
            gexDhExchangeHash.setClientDHPublicKey(
                    ((DhGexExchangeHash) exchangeHash).getClientDHPublicKey());
            gexDhExchangeHash.setServerDHPublicKey(
                    ((DhGexExchangeHash) exchangeHash).getServerDHPublicKey());
        }
        return gexDhExchangeHash;
    }
}
