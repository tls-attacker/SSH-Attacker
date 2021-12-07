package de.rub.nds.sshattacker.core.crypto.kex;

import java.math.BigInteger;

public class RsaKeyExchange extends KeyExchange {

    private BigInteger exponent;
    private BigInteger modulus;

    @Override
    public void computeSharedSecret() {
        byte[] randomBytes = new byte[48];
        random.nextBytes(randomBytes);
        sharedSecret = new BigInteger(randomBytes);
    }

    public BigInteger getExponent(){
        return exponent;
    }

    public void setExponent(BigInteger exponent){
        this.exponent = exponent;
    }

    public BigInteger getModulus(){
        return modulus;
    }

    public void setModulus(BigInteger modulus){
        this.modulus = modulus;
    }

    public void setSharedSecret(BigInteger sharedSecret){
        this.sharedSecret = sharedSecret;
    }
}
