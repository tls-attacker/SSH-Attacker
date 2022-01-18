package de.rub.nds.sshattacker.core.crypto.kex;

import de.rub.nds.sshattacker.core.crypto.keys.RsaPublicKey;

import java.math.BigInteger;

public class RsaKeyExchange extends KeyExchange {

    private RsaPublicKey publicKey;

    // KLEN in RFC 4432 (in bits)
    private int modulusLength;

    // HLEN in RFC 4432 (in bits)
    private int hashLength;

    @Override
    public void computeSharedSecret() {
        // Calculation of maximum number of bits taken from RFC 4432
        int maximumBits = (modulusLength - 2 * hashLength - 49);
        sharedSecret = new BigInteger(maximumBits, random);
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

    public int getHashLength() {
        return hashLength;
    }

    public void setHashLength(int hashLength) {
        this.hashLength = hashLength;
    }

    public int getModulusLength() {
        return modulusLength;
    }

    /**
     * @param modulusLength length of the RSA modulus in bits
     */
    public void setModulusLength(int modulusLength) {
        this.modulusLength = modulusLength;
    }

    public void setSharedSecret(BigInteger sharedSecret){
        this.sharedSecret = sharedSecret;
    }
}
