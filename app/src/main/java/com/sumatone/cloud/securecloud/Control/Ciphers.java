package com.sumatone.cloud.securecloud.Control;

/**
 * Created by alfainfinity on 04/11/15.
 */

import java.math.*;

public class Ciphers {
    public static byte[] pohligHellmanEncipher(byte[] msg, BigInteger e, BigInteger p) {
        //Compute the plaintext block size
        int blockSize = (p.bitLength() - 1) / 8;
        //Check the enciphering exponent
        if (!(p.subtract(BigInteger.ONE).gcd(e).equals(BigInteger.ONE)))
            throw new IllegalArgumentException
                    ("Enciphering key is not relatively prime to (modulus minus one).");
        byte ba[][] = block(pad(msg, blockSize), blockSize);
        //Begin the enciphering
        for (int i = 0; i < ba.length; i++) ba[i] = getBytes(new BigInteger(1, ba[i]).modPow(e, p));
        //Return to a 1D array.
        //The ciphertext block size is one byte greater than plaintext block size.
        return unBlock(ba, blockSize + 1);
    }

    public static byte[] pohligHellmanDecipher(byte[] msg, BigInteger d, BigInteger p) {
        //Compute the ciphertext block size
        int blockSize = (p.bitLength() - 1) / 8 + 1;
        //Check the deciphering exponent
        if (!(p.subtract(BigInteger.ONE).gcd(d).equals(BigInteger.ONE)))
            throw new IllegalArgumentException
                    ("Deciphering key is not relatively prime to (modulus minus one).");
        byte[][] ba = block(msg, blockSize);
        //Begin the deciphering
        for (int i = 0; i < ba.length; i++)
            ba[i] = getBytes(new
                    BigInteger(1, ba[i]).modPow(d, p));
        //Go from blocks to a 1D array, and remove padding;//return this
        return unPad(unBlock(ba, blockSize - 1), blockSize - 1);
    }

    private static byte[][] block(byte[] msg, int blockSize) {
        //Create a 2D array of bytes corresponding to the message-all blocks should be //full
        int numberOfBlocks = msg.length / blockSize;
        byte[][] ba = new byte[numberOfBlocks][blockSize];
        for (int i = 0; i < numberOfBlocks; i++)
            for (int j = 0; j < blockSize; j++) ba[i][j] = msg[i * blockSize + j];
        return ba;
    }

    private static byte[] unBlock(byte[][] ba, int blockSize) {
        //Create the 1D array in which to place the enciphered blocks
        byte[] m2 = new byte[ba.length * blockSize];
        //Place the blocks in the 1D array
        for (int i = 0; i < ba.length; i++) {
            int j = blockSize - 1;
            int k = ba[i].length - 1;
            while (k >= 0) {
                m2[i * blockSize + j] = ba[i][k];
                k--;
                j--;
            }
        }
        return m2;
    }

    private static byte[] unPad(byte[] msg, int blockSize) {
        //Determine the amount of padding-just look at last block
        int numberOfPads = (msg[msg.length - 1] + 256) % 256;
        //Chop off the padding and return the array
        byte[] answer = new byte[msg.length - numberOfPads];
        System.arraycopy(msg, 0, answer, 0, answer.length);
        return answer;
    }


    //Method to rectify the extra bit problem of the toByteArray() method
    private static byte[] getBytes(BigInteger big) {
        byte[] bigBytes = big.toByteArray();
        if (big.bitLength() % 8 != 0) return bigBytes;
        else {
            byte[] smallerBytes = new byte[big.bitLength() / 8];
            System.arraycopy(bigBytes, 1, smallerBytes, 0, smallerBytes.length);
            return smallerBytes;
        }
    }

    private static byte[] pad(byte[] msg, int blockSize) {
        //Check that block size is proper for PKCS#5 padding
        if (blockSize < 1 || blockSize > 255) throw new
                IllegalArgumentException("Block size must be between 1 and 255.");
        //Pad the message
        int numberToPad = blockSize - msg.length % blockSize;
        byte[] paddedMsg = new byte[msg.length + numberToPad];
        System.arraycopy(msg, 0, paddedMsg, 0, msg.length);
        for (int i = msg.length; i < paddedMsg.length; i++) paddedMsg[i] = (byte) numberToPad;
        return paddedMsg;
    }




//...Other methods
}
