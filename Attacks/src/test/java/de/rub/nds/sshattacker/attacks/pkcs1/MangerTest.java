/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.attacks.pkcs1;

import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.attacks.pkcs1.oracles.MockOracle;
import de.rub.nds.sshattacker.attacks.pkcs1.util.OaepConverter;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemReader;
import org.junit.jupiter.api.Test;

import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;

import javax.crypto.NoSuchPaddingException;

public class MangerTest {

    @Test
    public void mangerMockAttackTest() {
        String encryptedSecret =
                "03B9D2D53E62921B12C0E57B5186F962292EB14E537560396F2FC30DE6B07899183ECC7F6690E58C8A4A5B9350D1C4BBD2EA791F11FB8DFD0815800926BF8A294C9A3942BE3B732F75E1F4FE56767ACF3C64926B00C9BF551677C4C125A599CAC3121BB6A895581E9A900BA8EF805147AAB485FFC511E1D8417BF1F874FD042E";
        BigInteger secret =
                new BigInteger(
                        "1E7FF30E4980A519B4C6B499F58017D0AF02F62D30D3A349BCAD640588932DBAFD9557D5897E26D7130F252B1BCAD18331FDE557EAA10431FA73A3E86DA76B598D2F35EBF68E039B74A5DD309632823F6A91",
                        16);

        RSAPrivateKey privateKey;
        RSAPublicKey publicKey;
        MockOracle oracle;
        ClassLoader loader = Thread.currentThread().getContextClassLoader();
        Security.addProvider(new BouncyCastleProvider());
        try {
            // Read private key file and create key factory
            String privateKeyFileName = "rsa_1024";
            Reader fileReader =
                    new FileReader(
                            Objects.requireNonNull(loader.getResource(privateKeyFileName))
                                    .getFile());
            PemReader reader = new PemReader(fileReader);
            byte[] content = reader.readPemObject().getContent();
            KeyFactory factory = KeyFactory.getInstance("RSA");

            // Create private key from file
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(content);
            privateKey = (RSAPrivateKey) factory.generatePrivate(privateKeySpec);

            // Read public key
            String publicKeyFileName = "rsa_1024.pub";
            Reader pubFileReader =
                    new FileReader(
                            Objects.requireNonNull(loader.getResource(publicKeyFileName))
                                    .getFile());
            PemReader pubReader = new PemReader(pubFileReader);
            byte[] pubContent = pubReader.readPemObject().getContent();

            // Create public key from file
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(pubContent);
            publicKey = (RSAPublicKey) factory.generatePublic(pubKeySpec);

            oracle = new MockOracle(publicKey, privateKey);

            byte[] encryptedSecretBytes = ArrayConverter.hexStringToByteArray(encryptedSecret);
            Manger attacker = new Manger(encryptedSecretBytes, oracle);
            attacker.attack();
            BigInteger solution = attacker.getSolution();

            BigInteger result =
                    OaepConverter.decodeSolution(
                            solution,
                            "SHA-1",
                            ((RSAPublicKey) oracle.getPublicKey()).getModulus().bitLength()
                                    / Byte.SIZE);

            CONSOLE.info("Encoded Solution: {}", solution);
            CONSOLE.info("Decoded Secret: {}", secret);

            assertEquals(secret, result);
        } catch (IOException
                | NoSuchAlgorithmException
                | InvalidKeySpecException
                | NoSuchPaddingException
                | InvalidKeyException e) {
            fail("Could not initialize Mock Oracle" + e.getLocalizedMessage());
        }
    }
}
