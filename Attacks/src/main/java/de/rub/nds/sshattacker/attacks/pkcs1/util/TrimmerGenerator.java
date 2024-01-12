/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.attacks.pkcs1.util;

import java.math.BigInteger;
import java.util.ArrayList;

public class TrimmerGenerator {

    public TrimmerGenerator() {}

    /**
     * Retrieves u/t paires for improved bb attack as mentioned by Bardou 2012
     *
     * @param maxPairs the maximum number of pairs to retrieve
     * @return an ArrayList of int arrays representing the pairs of integers
     */
    public ArrayList<int[]> getPaires(int maxPairs) {
        ArrayList<int[]> paires = new ArrayList<>();
        BigInteger u = BigInteger.valueOf(1);
        BigInteger t = BigInteger.valueOf(2);

        // as long as we are not above t < 2^12 and the max number of paires isn`t reached - go on
        // searching
        while ((t.compareTo(BigInteger.valueOf(2).pow(12)) < 0) && paires.size() < maxPairs) {
            BigInteger[] result = ensureRange(u, t);
            u = result[0];
            t = result[1];

            // while u and t are not coprime - add up u and test again
            // every run test if we are in range, otherwise correct
            while (u.gcd(t).compareTo(BigInteger.valueOf(1)) != 0) {
                u = u.add(BigInteger.ONE);
                BigInteger[] result2 = ensureRange(u, t);
                u = result2[0];
                t = result2[1];
            }

            // Pair found -> add to paires and add u one up
            paires.add(new int[] {u.intValue(), t.intValue()});
            u = u.add(BigInteger.ONE);
        }

        return paires;
    }

    private BigInteger[] ensureRange(BigInteger ucandidate, BigInteger tcandidate) {
        float quotient = ucandidate.floatValue() / tcandidate.floatValue();

        // if we get to big - choose next value for t, reset u to 1
        if (quotient >= (3.0F / 2.0F)) {
            ucandidate = BigInteger.valueOf(1);
            tcandidate = tcandidate.add(BigInteger.ONE);
            quotient = ucandidate.floatValue() / tcandidate.floatValue();
        }
        // test if wie are too small, add up u until we are above 2/3
        while (quotient <= (2.0F / 3.0F)) {
            ucandidate = ucandidate.add(BigInteger.ONE);
            quotient = ucandidate.floatValue() / tcandidate.floatValue();
        }

        // return if the range is hold
        return new BigInteger[] {ucandidate, tcandidate};
    }
}
