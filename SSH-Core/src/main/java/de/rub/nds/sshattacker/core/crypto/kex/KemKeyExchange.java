/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.kex;

import de.rub.nds.sshattacker.core.constants.KemAlgorithm;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import java.security.*;
import java.util.Arrays;
import javax.crypto.DecapsulateException;
import javax.crypto.KEM;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.provider.asymmetric.mlkem.BCMLKEMPublicKey;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeParameters;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimePublicKeyParameters;
import org.bouncycastle.pqc.jcajce.provider.ntruprime.BCSNTRUPrimePublicKey;

public class KemKeyExchange extends KeyEncapsulation<PublicKey> {

    private final KemAlgorithm kemAlgorithm;

    private KEM kem;
    private PrivateKey privateKey;

    public KemKeyExchange(KemAlgorithm kemAlgorithm) {
        super();
        this.kemAlgorithm = kemAlgorithm;
    }

    @Override
    public void generateKeyPair() throws CryptoException {
        KeyPairGenerator keyGen;
        try {
            keyGen = KeyPairGenerator.getInstance(kemAlgorithm.getJavaName());
            keyGen.initialize(kemAlgorithm.getParameterSpec());
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException(
                    "Unable to generate KEM key pair - key pair generator is not available");
        } catch (InvalidAlgorithmParameterException e) {
            throw new CryptoException(
                    "Unable to generate KEM key pair - invalid algorithm parameter", e);
        }
        KeyPair keyPair = keyGen.generateKeyPair();
        privateKey = keyPair.getPrivate();
        publicKey = keyPair.getPublic();
    }

    public KemAlgorithm getKemAlgorithm() {
        return kemAlgorithm;
    }

    public byte[] getPublicKeyBytes() {
        SubjectPublicKeyInfo pki = SubjectPublicKeyInfo.getInstance(getPublicKey().getEncoded());
        byte[] encodedPublicKey = pki.getPublicKeyData().getBytes();
        return switch (kemAlgorithm) {
            // BouncyCastle seems to return the public key as an ASN.1 encoded value for SNTRUP761
            case SNTRUP761 -> Arrays.copyOfRange(encodedPublicKey, 4, encodedPublicKey.length);
            case MLKEM768, MLKEM1024 -> encodedPublicKey;
        };
    }

    public void setPublicKey(byte[] encodedPublicKey) {
        switch (kemAlgorithm) {
            case SNTRUP761 ->
                    publicKey =
                            new BCSNTRUPrimePublicKey(
                                    new SNTRUPrimePublicKeyParameters(
                                            SNTRUPrimeParameters.sntrup761, encodedPublicKey));
            case MLKEM768, MLKEM1024 ->
                    publicKey =
                            new BCMLKEMPublicKey(
                                    new MLKEMPublicKeyParameters(
                                            (MLKEMParameters) kemAlgorithm.getParameterSpec(),
                                            encodedPublicKey));
        }
    }

    @Override
    public void encapsulate() throws CryptoException {
        if (publicKey == null) {
            throw new CryptoException("Unable to encapsulate - public key is null");
        }
        try {
            if (kem == null) {
                kem = KEM.getInstance(kemAlgorithm.getJavaName());
            }
            KEM.Encapsulator encapsulator = kem.newEncapsulator(publicKey);
            KEM.Encapsulated encapsulated = encapsulator.encapsulate();
            encapsulation = encapsulated.encapsulation();
            sharedSecret = encapsulated.key().getEncoded();
        } catch (InvalidKeyException e) {
            throw new CryptoException("Unable to encapsulate - invalid public key", e);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("Unable to encapsulate - invalid algorithm", e);
        }
    }

    @Override
    public void decapsulate() throws CryptoException {
        if (privateKey == null || encapsulation == null) {
            throw new CryptoException(
                    "Unable to decapsulate - either private key or encapsulation is null");
        }
        try {
            if (kem == null) {
                kem = KEM.getInstance(kemAlgorithm.getJavaName());
            }
            KEM.Decapsulator decapsulator = kem.newDecapsulator(privateKey);
            sharedSecret = decapsulator.decapsulate(encapsulation).getEncoded();
        } catch (InvalidKeyException e) {
            throw new CryptoException("Unable to decapsulate - invalid private key", e);
        } catch (DecapsulateException e) {
            throw new CryptoException("Unable to decapsulate - invalid encapsulation", e);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("Unable to decapsulate - invalid algorithm", e);
        }
    }
}
