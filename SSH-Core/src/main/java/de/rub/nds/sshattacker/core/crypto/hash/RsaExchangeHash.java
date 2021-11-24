/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.hash;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;

public class RsaExchangeHash extends ExchangeHash {

    protected byte[] encryptedSecret;
    protected byte[] transientKey;

    public RsaExchangeHash(SshContext context) {
        super(context);
    }

    public byte[] getEncryptedSecret() {
        return encryptedSecret;
    }

    public void setEncryptedSecret(byte[] encryptedSecret) {
        this.encryptedSecret = encryptedSecret;
    }

    public byte[] getTransientKey() {
        return transientKey;
    }

    public void setTransientKey(byte[] transientKey) {
        this.transientKey = transientKey;
    }

    @Override
    protected boolean areRequiredInputsMissing() {
        return super.areRequiredInputsMissing()
                || encryptedSecret == null
                || transientKey == null;
    }

    @Override
    protected byte[] getHashInput() {
        return ArrayConverter.concatenate(
                Converter.stringToLengthPrefixedBinaryString(clientVersion),
                Converter.stringToLengthPrefixedBinaryString(serverVersion),
                Converter.bytesToLengthPrefixedBinaryString(clientKeyExchangeInit),
                Converter.bytesToLengthPrefixedBinaryString(serverKeyExchangeInit),
                Converter.bytesToLengthPrefixedBinaryString(serverHostKey),
                Converter.bytesToLengthPrefixedBinaryString(transientKey),
                Converter.bytesToLengthPrefixedBinaryString(encryptedSecret),
                Converter.byteArrayToMpint(sharedSecret));
    }

    public static RsaExchangeHash from(ExchangeHash exchangeHash) {
        RsaExchangeHash rsaExchangeHash = new RsaExchangeHash(exchangeHash.context);
        rsaExchangeHash.setClientVersion(exchangeHash.clientVersion);
        rsaExchangeHash.setServerVersion(exchangeHash.serverVersion);
        rsaExchangeHash.setClientKeyExchangeInit(exchangeHash.clientKeyExchangeInit);
        rsaExchangeHash.setServerKeyExchangeInit(exchangeHash.serverKeyExchangeInit);
        rsaExchangeHash.setServerHostKey(exchangeHash.serverHostKey);
        rsaExchangeHash.setSharedSecret(exchangeHash.sharedSecret);
        if (exchangeHash instanceof RsaExchangeHash) {
            rsaExchangeHash.setEncryptedSecret(
                    ((RsaExchangeHash) exchangeHash).encryptedSecret);
            rsaExchangeHash.setTransientKey(
                    ((RsaExchangeHash) exchangeHash).transientKey);
        }
        return rsaExchangeHash;
    }
}
