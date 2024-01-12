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

/**
 * The MathHelper class provides various mathematical helper methods.
 */
public class MathHelper {

    public MathHelper() {}

    public static BigInteger floor(BigInteger a, BigInteger b) {
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
    public static BigInteger ceil(BigInteger a, BigInteger b) {
        BigInteger c = a.mod(b);
        if (c.compareTo(BigInteger.ZERO) > 0) {
            return a.divide(b).add(BigInteger.ONE);
        } else {
            return a.divide(b);
        }
    }

    /**
     * Finds the Greatest Common Divisor (GCD) of two integers.
     *
     * @param num1 The first integer
     * @param num2 The second integer
     * @return The GCD of the two integers
     */
    public static int findGCD(int num1, int num2) {
        if (num2 == 0) {
            return num1;
        }
        return findGCD(num2, num1 % num2);
    }

    /**
     * Finds the Least Common Multiple (LCM) of two integers.
     *
     * @param num1 The first integer
     * @param num2 The second integer
     * @return The LCM of the two integers
     */
    public static int findLCM(int num1, int num2) {
        return (num1 * num2) / findGCD(num1, num2);
    }

    /**
     * Finds the least common multiple (LCM) of a list of integers.
     *
     * @param numbers The list of integers
     * @return The least common multiple (LCM) of the given integers
     */
    public static int findLeastCommonMultiple(ArrayList<Integer> numbers) {
        int lcm_of_array_elements = 1;
        int n = numbers.size();

        for (int i = 0; i < n; i++)
            lcm_of_array_elements = findLCM(lcm_of_array_elements, numbers.get(i));

        return lcm_of_array_elements;
    }
}
