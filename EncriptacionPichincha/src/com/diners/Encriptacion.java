package com.diners;

import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.io.IOUtils;

import com.ibm.xml.crypto.util.Base64;

public class Encriptacion {

	public static String getSimetric() {
		byte[] aesKey = { 0 };

		try {
			InputStream privateKeyStream = Encriptacion.class.getResourceAsStream("PrivateKeyPichincha.key");
			String idLlave = new String(IOUtils.toByteArray(privateKeyStream));
			PrivateKey pk = getLlavePrivada(idLlave);
			Cipher pkCipher;
			InputStream symetricKeyStream = Encriptacion.class.getResourceAsStream("llaveSimetrica.key");
			pkCipher = Cipher.getInstance("RSA");
			pkCipher.init(Cipher.DECRYPT_MODE, pk);
			byte[] datosDecifrados = pkCipher.doFinal(Base64.decode(IOUtils.toByteArray(symetricKeyStream)));
			aesKey = new byte[256 / 8];
			aesKey = datosDecifrados;
		} catch (Exception e) {
			System.out.println(e.getMessage());
		}
		return new String(aesKey);
	}

	public static String desencriptacionPichincha(String dato) throws IOException {
		try {
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(2, new SecretKeySpec(getSimetric().getBytes(), "AES"));
			return new String(cipher.doFinal(Base64.decode(dato)));
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
		return "";
	}

	private static PrivateKey getLlavePrivada(String llavePrivada) {

		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Base64.decode(llavePrivada));

		KeyFactory kf;

		try {
			kf = KeyFactory.getInstance("RSA");
			return kf.generatePrivate(spec);

		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			e.printStackTrace();
		}

		return null;
	}
	
	public static String encriptacionPichincha(String dato) throws IOException {
		String datoCifrado = "";
		
		try {
			Cipher cipher = null;
			SecretKeySpec key = new SecretKeySpec(getSimetric().getBytes(), "AES");			
			cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			byte[] campoCifrado = cipher.doFinal(dato.getBytes());
			datoCifrado = Base64.encode(campoCifrado);		 
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
		 
		return datoCifrado;
	}
	
	public static void main(String[] args) {
		try {	
			if(args.length > 0) {
				String datos = desencriptacionPichincha(args[0]);
				System.out.println(datos);
			}
			else {
				//String encriptacion = encriptacionPichincha("423");
				//String encriptacion = desencriptacionPichincha("2plXTWa2Xn6ZlaU2SA6Ckw==");
				//System.out.println(encriptacion);
				String datos = desencriptacionPichincha("eS3fgTD1v3JjJTJjxLrT2aUgHdxzQB34ZU/WnsdI5q4=");
				System.out.println(datos);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
