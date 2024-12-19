/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.hash;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.sshattacker.core.constants.KeyExchangeFlowType;
import de.rub.nds.sshattacker.core.crypto.util.PublicKeyHelper;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.exceptions.MissingExchangeHashInputException;
import de.rub.nds.sshattacker.core.exceptions.NotImplementedException;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.KeyExchangeInitMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.config.Configurator;

/**
 * A utility class to perform exchange hash computations based on an ExchangeHashInputHolder
 * instance.
 */
public final class ExchangeHash {

    private static final Logger LOGGER = LogManager.getLogger();

    private ExchangeHash() {
        super();
    }

    /**
     * Computes the exchange hash for the given algorithm with the ExchangeHashInputHolder instance
     * present in the context.
     *
     * @param context SSH context containing the ExchangeHashInputHolder instance
     * @param algorithm Algorithm to compute the exchange hash for
     * @return The computed exchange hash bytes
     * @throws CryptoException Thrown whenever something went wrong during exchange hash
     *     computation.
     * @throws MissingExchangeHashInputException Thrown whenever required inputs to compute the hash
     *     are missing.
     * @throws NotImplementedException Thrown whenever hash computation for the given algorithm is
     *     not yet implemented.
     */
    public static byte[] computeHash(SshContext context, KeyExchangeAlgorithm algorithm)
            throws CryptoException {
        switch (algorithm.getFlowType()) {
            case DIFFIE_HELLMAN:
                return computeDhHash(algorithm, context.getExchangeHashInputHolder());
            case DIFFIE_HELLMAN_GROUP_EXCHANGE:
                if (context.isOldGroupRequestReceived()) {
                    return computeOldDhGexHash(algorithm, context.getExchangeHashInputHolder());
                } else {
                    return computeDhGexHash(algorithm, context.getExchangeHashInputHolder());
                }
            case ECDH:
                return computeEcdhHash(algorithm, context.getExchangeHashInputHolder());
            case RSA:
                return computeRsaHash(algorithm, context.getExchangeHashInputHolder());
            case HYBRID:
                return computeHybridHash(algorithm, context.getExchangeHashInputHolder());
            default:
                throw new NotImplementedException(
                        "Unable to compute exchange hash, hash computation for flow type "
                                + algorithm.getFlowType()
                                + " not implemented.");
        }
    }

    public static byte[] computeDhHash(
            KeyExchangeAlgorithm algorithm, ExchangeHashInputHolder inputHolder)
            throws CryptoException {
        if (algorithm.getFlowType() != KeyExchangeFlowType.DIFFIE_HELLMAN) {
            LOGGER.warn(
                    "Trying to compute DH exchange hash with a mismatching algorithm provided, this might fail.");
        }
        return compute(algorithm, prepareDhHashInput(inputHolder));
    }

    public static byte[] computeDhGexHash(
            KeyExchangeAlgorithm algorithm, ExchangeHashInputHolder inputHolder)
            throws CryptoException {
        if (algorithm.getFlowType() != KeyExchangeFlowType.DIFFIE_HELLMAN_GROUP_EXCHANGE) {
            LOGGER.warn(
                    "Trying to compute DH GEX exchange hash with a mismatching algorithm provided, this might fail.");
        }
        try {
            return compute(algorithm, prepareDhGexHashInput(inputHolder));
        } catch (MissingExchangeHashInputException e) {
            // Fallback to old DH GEX exchange hash
            try {
                return computeOldDhGexHash(algorithm, inputHolder);
            } catch (MissingExchangeHashInputException ignored) {
                // Both variants failed, throw the first exception from the original invocation
                throw e;
            }
        }
    }

    public static byte[] computeOldDhGexHash(
            KeyExchangeAlgorithm algorithm, ExchangeHashInputHolder inputHolder)
            throws CryptoException {
        if (algorithm.getFlowType() != KeyExchangeFlowType.DIFFIE_HELLMAN_GROUP_EXCHANGE) {
            LOGGER.warn(
                    "Trying to compute old DH GEX exchange hash with a mismatching algorithm provided, this might fail.");
        }
        return compute(algorithm, prepareOldDhGexHashInput(inputHolder));
    }

    public static byte[] computeEcdhHash(
            KeyExchangeAlgorithm algorithm, ExchangeHashInputHolder inputHolder)
            throws CryptoException {
        if (algorithm.getFlowType() != KeyExchangeFlowType.ECDH) {
            LOGGER.warn(
                    "Trying to compute ECDH exchange hash with a mismatching algorithm provided, this might fail.");
        }
        return compute(algorithm, prepareEcdhHashInput(inputHolder));
    }

    public static byte[] computeHybridHash(
            KeyExchangeAlgorithm algorithm, ExchangeHashInputHolder inputHolder)
            throws CryptoException {
        if (algorithm.getFlowType() != KeyExchangeFlowType.HYBRID) {
            LOGGER.warn(
                    "Trying to compute Hybrid exchange hash with a mismatching algorithm provided, this might fail.");
        }
        return compute(algorithm, prepareHybridHashInput(inputHolder));
    }

    public static byte[] computeRsaHash(
            KeyExchangeAlgorithm algorithm, ExchangeHashInputHolder inputHolder)
            throws CryptoException {
        if (algorithm.getFlowType() != KeyExchangeFlowType.RSA) {
            LOGGER.warn(
                    "Trying to compute RSA exchange hash with a mismatching algorithm provided, this might fail.");
        }
        return compute(algorithm, prepareRsaHashInput(inputHolder));
    }

    private static byte[] compute(KeyExchangeAlgorithm algorithm, byte[] input)
            throws CryptoException {
        LOGGER.debug("Exchange hash input: {}", () -> ArrayConverter.bytesToRawHexString(input));
        MessageDigest md;
        try {
            md = MessageDigest.getInstance(algorithm.getDigest());
        } catch (NoSuchAlgorithmException e) {
            LOGGER.error(
                    "There is no security provider supporting this hash function: {}",
                    algorithm.getDigest());
            LOGGER.debug(e);
            throw new CryptoException(
                    "Unable to calculate exchange hash because the required hash algorithm is not supported by any security provider.",
                    e);
        }
        byte[] hash = md.digest(input);
        LOGGER.info("Computed exchange hash: {}", () -> ArrayConverter.bytesToRawHexString(hash));
        return hash;
    }

    private static byte[] prepareCommonPrefixHashInput(ExchangeHashInputHolder inputHolder) {
        /*
         * The common prefix of all exchange hash inputs is:
         *   string    V_C, the client's identification string (CR and LF excluded)
         *   string    V_S, the server's identification string (CR and LF excluded)
         *   string    I_C, the payload of the client's SSH_MSG_KEXINIT
         *   string    I_S, the payload of the server's SSH_MSG_KEXINIT
         *   string    K_S, the host key
         */
        if (inputHolder.getClientVersion().isEmpty()) {
            throw new MissingExchangeHashInputException("Client version exchange message missing");
        }
        if (inputHolder.getServerVersion().isEmpty()) {
            throw new MissingExchangeHashInputException(
                    "[Common] Server version exchange message missing");
        }
        if (inputHolder.getClientKeyExchangeInit().isEmpty()) {
            throw new MissingExchangeHashInputException(
                    "[Common] Client key exchange init message missing");
        }
        if (inputHolder.getServerKeyExchangeInit().isEmpty()) {
            throw new MissingExchangeHashInputException(
                    "[Common] Server key exchange init message missing");
        }
        if (inputHolder.getServerHostKey().isEmpty()) {
            throw new MissingExchangeHashInputException("[Common] Server host key missing");
        }
        // Avoid log spam by adjusting the log level of the key exchange init message serializer
        Level oldLevel = LogManager.getLogger(KeyExchangeInitMessageSerializer.class).getLevel();
        Configurator.setLevel(KeyExchangeInitMessageSerializer.class.getName(), Level.OFF);
        byte[] prefix =
                ArrayConverter.concatenate(
                        Converter.stringToLengthPrefixedBinaryString(
                                inputHolder.getClientVersion().get().getIdentification()),
                        Converter.stringToLengthPrefixedBinaryString(
                                inputHolder.getServerVersion().get().getIdentification()),
                        Converter.bytesToLengthPrefixedBinaryString(
                                new KeyExchangeInitMessageSerializer(
                                                inputHolder.getClientKeyExchangeInit().get())
                                        .serialize()),
                        Converter.bytesToLengthPrefixedBinaryString(
                                new KeyExchangeInitMessageSerializer(
                                                inputHolder.getServerKeyExchangeInit().get())
                                        .serialize()),
                        Converter.bytesToLengthPrefixedBinaryString(
                                PublicKeyHelper.encode(inputHolder.getServerHostKey().get())));
        // Restore the old log level
        Configurator.setLevel(KeyExchangeInitMessageSerializer.class.getName(), oldLevel);
        return prefix;
    }

    private static byte[] prepareCommonSuffixHashInput(ExchangeHashInputHolder inputHolder) {
        /*
         * The common suffix of all exchange hash inputs is:
         *   mpint     K, the shared secret
         */
        if (inputHolder.getSharedSecret().isEmpty()) {
            throw new MissingExchangeHashInputException("[Common] Shared secret missing");
        }
        return Converter.bytesToLengthPrefixedBinaryString(inputHolder.getSharedSecret().get());
    }

    private static byte[] prepareDhHashInput(ExchangeHashInputHolder inputHolder) {
        /*
         * Exchange hash input for the named DH key exchange method:
         *   string    V_C, the client's identification string (CR and LF excluded)
         *   string    V_S, the server's identification string (CR and LF excluded)
         *   string    I_C, the payload of the client's SSH_MSG_KEXINIT
         *   string    I_S, the payload of the server's SSH_MSG_KEXINIT
         *   string    K_S, the host key
         *   mpint     e, exchange value sent by the client
         *   mpint     f, exchange value sent by the server
         *   mpint     K, the shared secret
         */
        if (inputHolder.getDhClientPublicKey().isEmpty()) {
            throw new MissingExchangeHashInputException("[DH] client public key missing");
        }
        if (inputHolder.getDhServerPublicKey().isEmpty()) {
            throw new MissingExchangeHashInputException("[DH] Server public key missing");
        }
        return ArrayConverter.concatenate(
                prepareCommonPrefixHashInput(inputHolder),
                Converter.bigIntegerToMpint(inputHolder.getDhClientPublicKey().get()),
                Converter.bigIntegerToMpint(inputHolder.getDhServerPublicKey().get()),
                prepareCommonSuffixHashInput(inputHolder));
    }

    private static byte[] prepareDhGexHashInput(ExchangeHashInputHolder inputHolder) {
        /*
         * Exchange hash input for the DH GEX key exchange method:
         *   string  V_C, the client's version string (CR and NL excluded)
         *   string  V_S, the server's version string (CR and NL excluded)
         *   string  I_C, the payload of the client's SSH_MSG_KEXINIT
         *   string  I_S, the payload of the server's SSH_MSG_KEXINIT
         *   string  K_S, the host key
         *   uint32  min, minimal size in bits of an acceptable group
         *   uint32  n, preferred size in bits of the group the server will send
         *   uint32  max, maximal size in bits of an acceptable group
         *   mpint   p, safe prime
         *   mpint   g, generator for subgroup
         *   mpint   e, exchange value sent by the client
         *   mpint   f, exchange value sent by the server
         *   mpint   K, the shared secret
         */
        if (inputHolder.getDhGexMinimalGroupSize().isEmpty()) {
            throw new MissingExchangeHashInputException("[DH GEX] Minimal group size missing");
        }
        if (inputHolder.getDhGexPreferredGroupSize().isEmpty()) {
            throw new MissingExchangeHashInputException("[DH GEX] Preferred group size missing");
        }
        if (inputHolder.getDhGexMaximalGroupSize().isEmpty()) {
            throw new MissingExchangeHashInputException("[DH GEX] Maximal group size missing");
        }
        if (inputHolder.getDhGexGroupModulus().isEmpty()) {
            throw new MissingExchangeHashInputException("[DH GEX] Group modulus missing");
        }
        if (inputHolder.getDhGexGroupGenerator().isEmpty()) {
            throw new MissingExchangeHashInputException("[DH GEX] Group generator missing");
        }
        if (inputHolder.getDhGexClientPublicKey().isEmpty()) {
            throw new MissingExchangeHashInputException("[DH GEX] Client public key missing");
        }
        if (inputHolder.getDhGexServerPublicKey().isEmpty()) {
            throw new MissingExchangeHashInputException("[DH GEX] Server public key missing");
        }
        return ArrayConverter.concatenate(
                prepareCommonPrefixHashInput(inputHolder),
                ArrayConverter.intToBytes(
                        inputHolder.getDhGexMinimalGroupSize().get(),
                        DataFormatConstants.UINT32_SIZE),
                ArrayConverter.intToBytes(
                        inputHolder.getDhGexPreferredGroupSize().get(),
                        DataFormatConstants.UINT32_SIZE),
                ArrayConverter.intToBytes(
                        inputHolder.getDhGexMaximalGroupSize().get(),
                        DataFormatConstants.UINT32_SIZE),
                Converter.bigIntegerToMpint(inputHolder.getDhGexGroupModulus().get()),
                Converter.bigIntegerToMpint(inputHolder.getDhGexGroupGenerator().get()),
                Converter.bigIntegerToMpint(inputHolder.getDhGexClientPublicKey().get()),
                Converter.bigIntegerToMpint(inputHolder.getDhGexServerPublicKey().get()),
                prepareCommonSuffixHashInput(inputHolder));
    }

    private static byte[] prepareOldDhGexHashInput(ExchangeHashInputHolder inputHolder) {
        /*
         * Exchange hash input for the DH GEX key exchange method:
         *   string  V_C, the client's version string (CR and NL excluded)
         *   string  V_S, the server's version string (CR and NL excluded)
         *   string  I_C, the payload of the client's SSH_MSG_KEXINIT
         *   string  I_S, the payload of the server's SSH_MSG_KEXINIT
         *   string  K_S, the host key
         *   uint32  n, preferred size in bits of the group the server will send
         *   mpint   p, safe prime
         *   mpint   g, generator for subgroup
         *   mpint   e, exchange value sent by the client
         *   mpint   f, exchange value sent by the server
         *   mpint   K, the shared secret
         */
        if (inputHolder.getDhGexPreferredGroupSize().isEmpty()) {
            throw new MissingExchangeHashInputException(
                    "[Old DH GEX] Preferred group size missing");
        }
        if (inputHolder.getDhGexGroupModulus().isEmpty()) {
            throw new MissingExchangeHashInputException("[Old DH GEX] Group modulus missing");
        }
        if (inputHolder.getDhGexGroupGenerator().isEmpty()) {
            throw new MissingExchangeHashInputException("[Old DH GEX] Group generator missing");
        }
        if (inputHolder.getDhGexClientPublicKey().isEmpty()) {
            throw new MissingExchangeHashInputException("[Old DH GEX] Client public key missing");
        }
        if (inputHolder.getDhGexServerPublicKey().isEmpty()) {
            throw new MissingExchangeHashInputException("[Old DH GEX] Server public key missing");
        }
        return ArrayConverter.concatenate(
                prepareCommonPrefixHashInput(inputHolder),
                ArrayConverter.intToBytes(
                        inputHolder.getDhGexPreferredGroupSize().get(),
                        DataFormatConstants.UINT32_SIZE),
                Converter.bigIntegerToMpint(inputHolder.getDhGexGroupModulus().get()),
                Converter.bigIntegerToMpint(inputHolder.getDhGexGroupGenerator().get()),
                Converter.bigIntegerToMpint(inputHolder.getDhGexClientPublicKey().get()),
                Converter.bigIntegerToMpint(inputHolder.getDhGexServerPublicKey().get()),
                prepareCommonSuffixHashInput(inputHolder));
    }

    private static byte[] prepareHybridHashInput(ExchangeHashInputHolder inputHolder) {
        /*
         * Exchange hash input for the ECDH key exchange method:
         * string V_C, client's identification string (CR and LF excluded)
         * string V_S, server's identification string (CR and LF excluded)
         * string I_C, payload of the client's SSH_MSG_KEXINIT
         * string I_S, payload of the server's SSH_MSG_KEXINIT
         * string K_S, server's public host key
         * string Q_C, client's ephemeral public key octet
         * string Q_S, server's ephemeral public key octet
         * mpint K, encoded shared secret
         */
        if (inputHolder.getHybridClientPublicKey().isEmpty()) {
            throw new MissingExchangeHashInputException("[Hybrid] Client public key missing");
        }
        if (inputHolder.getHybridServerPublicKey().isEmpty()) {
            throw new MissingExchangeHashInputException("[Hybrid] Server public key missing");
        }
        return ArrayConverter.concatenate(
                prepareCommonPrefixHashInput(inputHolder),
                Converter.bytesToLengthPrefixedBinaryString(
                        inputHolder.getHybridClientPublicKey().get()),
                Converter.bytesToLengthPrefixedBinaryString(
                        inputHolder.getHybridServerPublicKey().get()),
                prepareCommonSuffixHashInput(inputHolder));
    }

    private static byte[] prepareEcdhHashInput(ExchangeHashInputHolder inputHolder) {
        /*
         * Exchange hash input for the ECDH key exchange method:
         *   string   V_C, client's identification string (CR and LF excluded)
         *   string   V_S, server's identification string (CR and LF excluded)
         *   string   I_C, payload of the client's SSH_MSG_KEXINIT
         *   string   I_S, payload of the server's SSH_MSG_KEXINIT
         *   string   K_S, server's public host key
         *   string   Q_C, client's ephemeral public key octet
         *   string   Q_S, server's ephemeral public key octet
         *   mpint    K,   shared secret
         */
        if (inputHolder.getEcdhClientPublicKey().isEmpty()) {
            throw new MissingExchangeHashInputException("[ECDH] Client public key missing");
        }
        if (inputHolder.getEcdhServerPublicKey().isEmpty()) {
            throw new MissingExchangeHashInputException("[ECDH] Server public key missing");
        }
        return ArrayConverter.concatenate(
                prepareCommonPrefixHashInput(inputHolder),
                Converter.bytesToLengthPrefixedBinaryString(
                        inputHolder.getEcdhClientPublicKey().get()),
                Converter.bytesToLengthPrefixedBinaryString(
                        inputHolder.getEcdhServerPublicKey().get()),
                prepareCommonSuffixHashInput(inputHolder));
    }

    private static byte[] prepareRsaHashInput(ExchangeHashInputHolder inputHolder) {
        /*
         * Exchange hash input for the RSA key exchange method:
         *   string    V_C, the client's identification string (CR and LF excluded)
         *   string    V_S, the server's identification string (CR and LF excluded)
         *   string    I_C, the payload of the client's SSH_MSG_KEXINIT
         *   string    I_S, the payload of the server's SSH_MSG_KEXINIT
         *   string    K_S, the host key
         *   string    K_T, the transient RSA key
         *   string    RSAES_OAEP_ENCRYPT(K_T, K), the encrypted secret
         *   mpint     K, the shared secret
         */
        if (inputHolder.getRsaTransientKey().isEmpty()) {
            throw new MissingExchangeHashInputException("[RSA] Transient public key missing");
        }
        if (inputHolder.getRsaEncryptedSecret().isEmpty()) {
            throw new MissingExchangeHashInputException("[RSA] Encrypted secret missing");
        }
        return ArrayConverter.concatenate(
                prepareCommonPrefixHashInput(inputHolder),
                Converter.bytesToLengthPrefixedBinaryString(
                        PublicKeyHelper.encode(inputHolder.getRsaTransientKey().get())),
                Converter.bytesToLengthPrefixedBinaryString(
                        inputHolder.getRsaEncryptedSecret().get()),
                prepareCommonSuffixHashInput(inputHolder));
    }
}
