/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.hash;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.crypto.keys.CustomDhPublicKey;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;
import java.math.BigInteger;

public class DhNamedExchangeHash extends ExchangeHash {

    private byte[] clientDHPublicKey;
    private byte[] serverDHPublicKey;

    public DhNamedExchangeHash(SshContext context) {
        super(context);
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
                Converter.byteArrayToMpint(clientDHPublicKey),
                Converter.byteArrayToMpint(serverDHPublicKey),
                Converter.byteArrayToMpint(sharedSecret));
    }

    public static DhNamedExchangeHash from(ExchangeHash exchangeHash) {
        DhNamedExchangeHash dhNamedExchangeHash = new DhNamedExchangeHash(exchangeHash.context);
        dhNamedExchangeHash.setClientVersion(exchangeHash.clientVersion);
        dhNamedExchangeHash.setServerVersion(exchangeHash.serverVersion);
        dhNamedExchangeHash.setClientKeyExchangeInit(exchangeHash.clientKeyExchangeInit);
        dhNamedExchangeHash.setServerKeyExchangeInit(exchangeHash.serverKeyExchangeInit);
        dhNamedExchangeHash.setServerHostKey(exchangeHash.serverHostKey);
        dhNamedExchangeHash.setSharedSecret(exchangeHash.sharedSecret);
        if (exchangeHash instanceof DhNamedExchangeHash) {
            dhNamedExchangeHash.setClientDHPublicKey(
                    ((DhNamedExchangeHash) exchangeHash).clientDHPublicKey);
            dhNamedExchangeHash.setServerDHPublicKey(
                    ((DhNamedExchangeHash) exchangeHash).serverDHPublicKey);
        }
        return dhNamedExchangeHash;
    }
}
