package com.sumatone.cloud.securecloud.Control;

/**
 * Created by alfainfinity on 04/11/15.
 */

import java.security.*;
import java.math.*;
import java.util.*;

public class PrimeGenerator {
    int minBitLength;
    int certainty;
    SecureRandom sr;

    public PrimeGenerator(int minBitLength, int certainty, SecureRandom sr) {

        //The bit length of the prime will exceed minBitLength

        if (minBitLength < 64)
            throw new IllegalArgumentException("Strong/Safe primes must be at least 64 bytes long.");
        this.minBitLength = minBitLength;
        this.certainty = certainty;
        this.sr = sr;
    }


    //This method returns a safe prime of form 2rt+1 where t is a large prime,

    //and the factorization of r is known

    //It also returns a generator for the safe prime

    //The zero-th slot in the resulting array is the safe prime

    //Slot 1 of the result is the generator

    public BigInteger[] getSafePrimeAndGenerator() {
        BigInteger[] p = new BigInteger[2];
        BigInteger r = BigInteger.valueOf(0x7fffffff);
        BigInteger t = new BigInteger(minBitLength - 30, certainty, sr);

        //p is the first prime in the sequence 2rt+1, 2*2rt+1, 2*3rt+1,...

        do {
            r = r.add(BigInteger.ONE);
            p[0] = new BigInteger("2").multiply(r).multiply(t).add(BigInteger.ONE);

        } while (!p[0].isProbablePrime(certainty));

        //We must get the prime factors of p-1=2rt

        //Put the prime factors in a Vector-list each prime factor only once

        Vector factors = new Vector();

        //Add t to the vector, since t is a prime factor of p-1=2rt

        factors.addElement(t);

        //We know 2 is a factor of p-1=2rt, so add 2 to the Vector

        factors.addElement(BigInteger.valueOf(2));

        //r may be prime-don’t factor it if you don’t have to

        if (r.isProbablePrime(10))
            factors.addElement(r);
            //otherwise, find the factors of r and add them to the Vector

        else {

            //Divide all the 2’s out of r, since 2 is already in the Vector

            while (r.mod(new BigInteger("2")).equals(BigInteger.ZERO)) {
                r = r.divide(new BigInteger("2"));
            }

            //We now get the prime factors of r, which should be small enough to
            //factor

            //Start with 3 - 2 is already in the Vector

            BigInteger divisor = BigInteger.valueOf(3);

            //Do not search for factors past the square root of r
            //Square the divisor for comparison to r

            BigInteger square = divisor.multiply(divisor);
            while (square.compareTo(r) <= 0) {

                //If this divisor divides r, add it to the Vector
                if (r.mod(divisor).equals(BigInteger.ZERO)) {
                    factors.addElement(divisor);

                    //Divide r by this divisor until it no longer divides
                    while (r.mod(divisor).equals(BigInteger.ZERO))
                        r = r.divide(divisor);
                }
                divisor = divisor.add(BigInteger.ONE);

                //Do not search for factors past the square root of r
                //Square the divisor for comparison to r
                square = divisor.multiply(divisor);
            }
        }

        //Now, start looking for a generator
        boolean isGenerator;
        BigInteger pMinusOne = p[0].subtract(BigInteger.ONE);
        BigInteger x, z, lnr;
        do {

            //Start by assuming the test # is a generator
            isGenerator = true;

            //Pick a random integer x smaller than the safe prime p
            x = new BigInteger(p[0].bitLength() - 1, sr);
            for (int i = 0; i < factors.size(); i++) {

                //Compute z as p-1 divided by the i-th prime factor in the Vector
                z = pMinusOne.divide((BigInteger) factors.elementAt(i));

                //Raise x to the z power modulo p
                lnr = x.modPow(z, p[0]);

                //If this equals 1, x is not a generator
                if (lnr.equals(BigInteger.ONE)) {
                    isGenerator = false;

                    //break-no reason to try the other prime factors for this failed x
                    break;
                }
            }

            //While x is not a generator, go back and pick another random x
        } while (!isGenerator);

        //If we get here, we found a generator-set it and return it
        p[1] = x;
        return p;
    }

    //getSafePrime() is identical to this, but does not search for a generator.
}
