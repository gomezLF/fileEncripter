package model;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class FileEncrypterDecrypter {

	/**
	 * PBKDF2 implementation based on what the Public-Key Cryptography Standards say
	 * on the subject. 
	 * @param password This field represents the password that the user typed and 
	 * this will have a derived key
	 * @param salt     the salt comprises random bits that are used as one of the 
	 * inputs in a key derivation function
	 * @param numberIterations   number of iterations for the PBEK function.
	 * @param keyLength   the length for the generated key in bytes.
	 * @return key derived from the function, it is in an array of bits.
	 */
	public byte[] PBKDF2(char[] password, byte[] salt, int numberIterations, int keyLength) {
		try {
			SecretKeyFactory secretKF = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
			PBEKeySpec PBEKeySpec = new PBEKeySpec(password, salt, numberIterations, keyLength);
			SecretKey secretKey = secretKF.generateSecret(PBEKeySpec);
			return secretKey.getEncoded();
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			throw new RuntimeException(e);
		}
	}



	/**
	 * This algorithm encrypts the given file using the generated 128-bit
	 * key from the PBKDF2 algorithm
	 * @param generatedKey  the key that will be used for the AES algorithm
	 * @param inputFile     the file that will be encrypted
	 * @param outputFile    the file that is encrypted
	 * @throws Exception 
	 */
	public void encryptFile(byte[] generatedKey, File inputFile, File outputFile) throws Exception {
		/*
		 * The cipher is initialized from the AES algorithm
		 */
		KeySpec keySpec = new SecretKeySpec(generatedKey, "AES");
		Cipher cipherAES = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipherAES.init(Cipher.ENCRYPT_MODE, (SecretKeySpec) keySpec);

		/*
		 * The input/output streams are initialized to read the files
		 */
		FileInputStream fileInputStream = new FileInputStream(inputFile);
		FileOutputStream fileOutputStream = new FileOutputStream(outputFile);

		/*
		 * The size of the buffer is set, in this case 64 bytes
		 */
		int bufferBytesSize = Math.min(fileInputStream.available(), 64);
		byte[] buffer = new byte[bufferBytesSize];
		
		/*
		 * If bytes still fit in the buffer, keep reading the input file
		 */
		while (buffer.length == 64) {
			fileInputStream.read(buffer);
			byte[] bufferEncrypted = cipherAES.update(buffer);
			fileOutputStream.write(bufferEncrypted);
			bufferBytesSize = Math.min(fileInputStream.available(), 64);
			buffer = new byte[bufferBytesSize];
		}
		fileInputStream.read(buffer);
		byte[] encryptedBuffer = cipherAES.doFinal(buffer);
		fileOutputStream.write(encryptedBuffer);

		fileInputStream.close();
		fileOutputStream.close();

	}
	
	/**
	 * This algorithm decrypts the given file given using the generated 128-bit
	 * 
	 * @param keyAES this key is used for the AES algorithm.
	 * @param inputFile  path location of the input file.
	 * @param outputFile path location of the out put file. 
	 * @throws Exception
	 */
	public void decryptFile(byte[] keyAES, File inputFile, File outputFile) throws Exception {
	
		
		KeySpec keySpec = new SecretKeySpec(keyAES, "AES");
		Cipher cipherAES = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipherAES.init(Cipher.DECRYPT_MODE, (SecretKeySpec) keySpec);		
		
		FileInputStream fileInputStream = new FileInputStream(inputFile);
		FileOutputStream fileOutputStream = new FileOutputStream(outputFile);
		
		int bufferBytesSize = Math.min(fileInputStream.available(), 64);
		byte[] buffer = new byte[bufferBytesSize];
		while (buffer.length == 64) {
			fileInputStream.read(buffer);
			byte[] bufferEncrypted = cipherAES.update(buffer);
			fileOutputStream.write(bufferEncrypted);
			bufferBytesSize = Math.min(fileInputStream.available(), 64);
			buffer = new byte[bufferBytesSize];
		}
		fileInputStream.read(buffer);
		byte[] encryptedBuffer = cipherAES.doFinal(buffer);
		fileOutputStream.write(encryptedBuffer);
		
		fileInputStream.close();
		fileOutputStream.close();
		
//		File decriptedFile = new File(out.getAbsolutePath());
//		String newHash = computeSHA1(decriptedFile);
		
	}

	/**
	 * This algorithm is the cryptographic hash function, which generates a 160-bit (20-byte) 
	 * hash from any input value.
	 * @param inputFile     the file that will be encrypted
	 * @param outputFile    the file that is encrypted
	 * @throws Exception
	 */
	public void generateSHA1(File inputFile, File outputFile) throws Exception {
		MessageDigest sha1 = MessageDigest.getInstance("SHA1");
		FileInputStream fileInputStream = new FileInputStream(inputFile);
		FileOutputStream fileOutputStream = new FileOutputStream(outputFile);

		byte[] dataBytes = new byte[1024];
		int readFile = 0;
		while ((readFile = fileInputStream.read(dataBytes)) != -1) {
			sha1.update(dataBytes, 0, readFile);
		}
		;
		byte[] hashBytes = sha1.digest();

		StringBuffer bufferString = new StringBuffer();
		for (int i = 0; i < hashBytes.length; i++) {
			bufferString.append(Integer.toString((hashBytes[i] & 0xff) + 0x100, 16).substring(1));
		}
		String fileHash = bufferString.toString();
		
		fileOutputStream.write(fileHash.getBytes(Charset.forName("UTF-8")));
		
		fileInputStream.close();
		fileOutputStream.close();

	}
	/**
	 * This algorithm generates the sha1 
	 * @param file
	 * @return
	 * @throws Exception
	 */
	public String computeSHA1(File file) throws Exception {
		MessageDigest sha1 = MessageDigest.getInstance("SHA1");
		FileInputStream fis = new FileInputStream(file);

		byte[] data = new byte[1024];
		int read = 0;
		while ((read = fis.read(data)) != -1) {
			sha1.update(data, 0, read);
		}
		;
		byte[] hashBytes = sha1.digest();

		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < hashBytes.length; i++) {
			sb.append(Integer.toString((hashBytes[i] & 0xff) + 0x100, 16).substring(1));
		}

		String fileHash = sb.toString();
		fis.close();
		return fileHash;
	}
	
	/**
	 * This algorithm is used to verify if sha1 of the input file is the same as the hash 
	 * generated by the generateSHA1 algorithm
	 * @param inputFile
	 * @param sha1
	 * @return true if the sha1 of the input file is the same that was generated by the
	 * generateSHA1 algorithm
	 * @throws Exception
	 */
	public boolean verifySHA1(File inputFile, File sha1) throws Exception {
		String inputHashFile = null;
		BufferedReader bufferedReader = new BufferedReader(new FileReader(sha1));
		while ((inputHashFile = bufferedReader.readLine()) != null) {
			inputHashFile = inputHashFile.trim();
			break;
		}
		bufferedReader.close();
		
		String sha1InputFile = computeSHA1(inputFile);
		
		return sha1InputFile.equals(inputHashFile);
		
	}

}
