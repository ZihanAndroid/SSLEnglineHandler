package model.sslEngineUtil;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.KeyGenerator;
import java.security.KeyStore;
import static java.security.KeyStore.*;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.File;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.UnrecoverableEntryException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.SecureRandom;
import java.security.Key;

public class KeyStoreUtil{
	KeyStore keyStore = KeyStore.getInstance("pkcs12");
	KeyGenerator keyGen = null;
	
	public KeyStoreUtil(String passwd, String secretKeyMethod, int secretKeySize) throws KeyStoreException,IOException, NoSuchAlgorithmException,CertificateException{
		keyGen = KeyGenerator.getInstance(secretKeyMethod);
		keyGen.init(secretKeySize, new SecureRandom());
		keyStore.load(null,passwd.toCharArray());
	}
	public KeyStoreUtil(File file, String passwd, String secretKeyMethod, int secretKeySize) throws KeyStoreException,IOException, NoSuchAlgorithmException,CertificateException{
		keyGen = KeyGenerator.getInstance(secretKeyMethod);
		keyGen.init(secretKeySize, new SecureRandom());
		loadKeyStore(file,passwd);
	}
	public void emptyKeyStore(String passwd)throws IOException, NoSuchAlgorithmException,NoSuchAlgorithmException,CertificateException{
		keyStore.load(null,passwd.toCharArray());
	}
	public KeyStore loadKeyStore(File file, String passwd)	throws IOException, NoSuchAlgorithmException, CertificateException{
		try(FileInputStream fis = new FileInputStream(file)){
			keyStore.load(fis,passwd.toCharArray());
		}catch(IOException e){
			throw e;
		}
		System.out.println("KeyStore loaded");
		return keyStore;
	}
	public void storeKeyStore(File file, String passwd) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException{
		try(FileOutputStream fos = new FileOutputStream(file)){
			keyStore.store(fos,passwd.toCharArray());
		}catch(IOException e){
			throw e;
		}
		System.out.println("KeyStore stored");
	}
	public KeyStore getKeyStore(){
		return keyStore;
	}
	
	
	//for SecretKey
	public void setSecretKeyGenerator(String method, int size) throws KeyStoreException,NoSuchAlgorithmException{
		keyGen = KeyGenerator.getInstance(method);
		keyGen.init(size, new SecureRandom());
	}
	public SecretKey generateSecretKey(){
		SecretKey key = keyGen.generateKey();
		return key;
	}
	public void saveSecretKey(SecretKey key, String keyName, String protect)throws KeyStoreException{
		KeyStore.SecretKeyEntry keyEntry = new KeyStore.SecretKeyEntry(key);
		PasswordProtection keyProtection = new PasswordProtection(protect.toCharArray());
		keyStore.setEntry(keyName, keyEntry, keyProtection);
	}
	public SecretKey getSecretKey(String keyName, String protect) throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException{
		KeyStore.SecretKeyEntry key = (KeyStore.SecretKeyEntry)keyStore.getEntry(keyName,new PasswordProtection(protect.toCharArray()));
		return key.getSecretKey();
	}
	
	public static String keyToHexString(Key key){
		byte[] bytes = key.getEncoded();
		StringBuilder strBuilder = new StringBuilder();
		for(byte b : bytes){
			String str = Integer.toHexString(b & 0xFF);
			if(str.length() == 1){
				str = "0"+str;
			}
			strBuilder.append(str);
		}
		return strBuilder.toString().toUpperCase();
	}
	/*
	public static void main(String[] args){
		try{
			File file = new File("JCA/keyStore/key/keyStore");
			String keyStorePasswd = new String("KeyStore_Protection_Password");
			String keyProtect = new String("Key_Protection_Password");
			
			System.out.println("AES-256");
			KeyStoreUtil keyStore = new KeyStoreUtil("AES",256,keyStorePasswd);
			SecretKey key = keyStore.generateSecretKey();
			
			System.out.println("The secret key generated:");
			System.out.println(keyToHexString(key));
			System.out.println("\n");
			
			keyStore.saveSecretKey(key, "myKey", keyProtect);
			keyStore.storeKeyStore(file, keyStorePasswd);
			
			keyStore.loadKeyStore(file,keyStorePasswd);
			SecretKey secretKey = keyStore.getSecretKey("myKey",keyProtect);
			
			System.out.println("The secret key retrieved:");
			System.out.println(keyToHexString(secretKey));
			System.out.println("\n");
			
			System.out.println("AES-128");
			keyStore.setSecretKeyGenerator("AES",128);
			SecretKey newKey = keyStore.generateSecretKey();
			System.out.println("The secret key generated:");
			System.out.println(keyToHexString(newKey));
			System.out.println("\n");
			
		}catch(Exception e){
			e.printStackTrace();
		}
	}
	*/
}