package de.rub.nds.sshattacker.core.crypto.kex;

import de.rub.nds.sshattacker.core.util.RsaPublicKey;

import java.math.BigInteger;

public class RsaKeyExchange extends KeyExchange {

    private RsaPublicKey publicKey;

    @Override
    public void computeSharedSecret() {
        byte[] randomBytes = new byte[48];
        random.nextBytes(randomBytes);
        sharedSecret = new BigInteger(randomBytes);
    }

    public void setPublicKey(RsaPublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public RsaPublicKey getPublicKey() {
        return publicKey;
    }

    public BigInteger getExponent(){
        return publicKey.getPublicExponent();
    }

    public BigInteger getModulus(){
        return publicKey.getModulus();
    }

    public void setSharedSecret(BigInteger sharedSecret){
        this.sharedSecret = sharedSecret;
    }
}
