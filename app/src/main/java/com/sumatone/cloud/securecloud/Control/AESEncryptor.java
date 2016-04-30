package com.sumatone.cloud.securecloud.Control;//package com.javaingrab.security.encrypt;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import java.io.Serializable;


public class AESEncryptor {

    public ReturnObject encrypt(String fname) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);  //using AES-256
        SecretKey key = keyGen.generateKey();  //generating key
        Cipher aesCipher = Cipher.getInstance("AES");  //getting cipher for AES
        aesCipher.init(Cipher.ENCRYPT_MODE, key);  //initializing cipher for encryption with key

        //creating file output stream to write to file
  /*try(FileOutputStream fos = new FileOutputStream(fname+".aes")){
   //creating object output stream to write objects to file
   ObjectOutputStream oos = new ObjectOutputStream(fos);
   oos.writeObject(key);  //saving key to file for use during decryption*/

        //creating file input stream to read contents for encryption
        try {
            InputStream fis = new ByteArrayInputStream(fname.getBytes());
            //creating cipher output stream to write encrypted contents

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

            CipherOutputStream cos = new CipherOutputStream(outputStream, aesCipher);
            int read;
            byte buf[] = new byte[4096];
            while ((read = fis.read(buf)) != -1)  //reading from file
                cos.write(buf, 0, read);  //encrypting and writing to file
            byte arrAfterEncrytion[] = outputStream.toByteArray();

            return new ReturnObject(arrAfterEncrytion, key.getEncoded());

        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    public byte[] decrypt(String fname, final String dKey) throws Exception {
        SecretKey key = null;

        //creating file input stream to read from file

        key = new SecretKey() {
            @Override
            public String getAlgorithm() {
                return "AES";
            }

            @Override
            public String getFormat() {
               return "RAW";
            }

            @Override
            public byte[] getEncoded() {
                return dKey.getBytes();
            }
        };  //reading key used for encryption

        Cipher aesCipher = Cipher.getInstance("AES");  //getting cipher for AES
        aesCipher.init(Cipher.DECRYPT_MODE, key);  //initializing cipher for decryption with key
        //creating file output stream to write back original contents
        ByteArrayInputStream fis=new ByteArrayInputStream(fname.getBytes());
        ByteArrayOutputStream fos=new ByteArrayOutputStream();
        try (CipherInputStream cis = new CipherInputStream(fis, aesCipher)) {
            int read;
            byte buf[] = new byte[4096];
            while ((read = cis.read(buf)) != -1)  //reading from file
                fos.write(buf, 0, read);  //decrypting and writing to file

            return fos.toByteArray();
        }


    }

    public static void main(String[] args) throws Exception {
        AESEncryptor obj = new AESEncryptor();
        //long start = System.currentTimeMillis();
        ReturnObject object=obj.encrypt("Prince");
        System.out.println(object.getOutputBytes());
//obj.encrypt("CAT2-LAB");
        //long end = System.currentTimeMillis();
       // long diff = end - start;
       // System.out.println("Encryption Time is : " + diff);
        //long start1 = System.currentTimeMillis();
        byte [] ar=new byte[128];
        byte [] dec=obj.decrypt(object.getOutputBytes().toString(), object.getKey().toString());
        System.out.println(new String(dec,"UTF-8"));
//  obj.decrypt(".doc.aes.dec");
        //long end1 = System.currentTimeMillis();
        //long diff1 = end1 - start1;
        //System.out.println("Decryption Time is : " + diff1);
    }

    public class ReturnObject implements Serializable {

        private byte[] outputBytes;
        private byte[] key;

        public ReturnObject(byte[] outputBytes, byte[] key) {
            this.outputBytes = outputBytes;
            this.key = key;
        }

        public byte[] getOutputBytes() {
            return outputBytes;
        }

        public void setOutputBytes(byte[] outputBytes) {
            this.outputBytes = outputBytes;
        }

        public byte[] getKey() {
            return key;
        }

        public void setKey(byte[] key) {
            this.key = key;
        }
    }

}