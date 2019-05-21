import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import security.DGK.DGKGenerator;
import security.DGK.DGKPrivateKey;
import security.DGK.DGKPublicKey;
import security.paillier.PaillierCipher;
import security.paillier.PaillierKeyPairGenerator;
import security.paillier.PaillierPublicKey;
import security.paillier.PaillierPrivateKey;
import security.socialistmillionaire.alice;
import security.socialistmillionaire.bob;


public class Main 
{
	private static boolean isAlice = false;
	
	public static void main(String [] args) throws NoSuchAlgorithmException, IOException
	{
		//RSAKeyPairGenerator();
		
		// Build DGK Keys
		DGKGenerator gen = new DGKGenerator(16, 160, 1024);
		KeyPair DGK = gen.generateKeyPair();
		DGKPrivateKey x = (DGKPrivateKey) DGK.getPrivate();
		DGKPublicKey y = (DGKPublicKey) DGK.getPublic();
		
		// Build Paillier Keys
		PaillierKeyPairGenerator p = new PaillierKeyPairGenerator();
		p.initialize(1024, null);
		KeyPair pe = p.generateKeyPair();
		PaillierPublicKey a = (PaillierPublicKey) pe.getPublic();
		PaillierPrivateKey b = (PaillierPrivateKey) pe.getPrivate();
		
		// Paillier Test Addition
		
		// Paillier Test Multiplication
		
		// DGK Test Addition
		
		// DGK Test Multiplication
		
		// Division Protocol Test, Paillier
		BigInteger D = new BigInteger("100");
		D = PaillierCipher.encrypt(D, a);
		if (isAlice)
		{
			Socket s = new Socket("192.168.147.100", 9254);
			alice al = new alice(s, a, y, false, null);
			try 
			{
				al.division(D, 2);
			} 
			catch (ClassNotFoundException e) 
			{
				e.printStackTrace();
			}
		}
		else
		{
			bob bo = new bob(null, a, b, y, x, false);
			try
			{
				bo.division(2);
			}
			catch (ClassNotFoundException e) 
			{
				e.printStackTrace();
			}
		}
		// Division Test, DGK
		
		// Comparison Protocol Test, Paillier
		if (isAlice)
		{
			
		}
		else
		{
			
		}
		// Comparison Test, DGK
		
	}
	
	/*
    public static void RSAKeyPairGenerator() throws NoSuchAlgorithmException, IOException 
    {
    	KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    	keyGen.initialize(1024);
    	KeyPair pair = keyGen.generateKeyPair();
    	PrivateKey privateKey = pair.getPrivate();
    	PublicKey publicKey = pair.getPublic();
    	System.out.println(privateKey.getAlgorithm());
    	System.out.println(privateKey.getFormat());
    	System.out.println(privateKey.getEncoded()[0]);

    	ByteArrayOutputStream bos = new ByteArrayOutputStream();
    	ObjectOutput out = null;
    	byte[] b;
    	try 
    	{
    		out = new ObjectOutputStream(bos);   
    		out.writeObject(privateKey);
    		out.flush();
    		b = bos.toByteArray(); 
    	}
    	finally 
    	{
    		try 
    		{
    			bos.close();
    		} 
    		catch (IOException ex) {
    			// ignore close exception
    		}
    	}
    	System.out.println(b[0]);
    	if (privateKey instanceof RSAPrivateKey)
    	{
    		System.out.println("IS RSA!");
    	}
    }
    */
}
