import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import security.DGK.DGKGenerator;
import security.DGK.DGKPrivateKey;
import security.DGK.DGKPublicKey;
import security.paillier.PaillierKeyPairGenerator;
import security.paillier.PaillierPK;
import security.paillier.PaillierSK;


public class Main 
{
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
		PaillierPK a = (PaillierPK) pe.getPublic();
		PaillierSK b = (PaillierSK) pe.getPrivate();
		
		// Paillier Test Addition
		
		// Paillier Test Multiplication
		
		// DGK Test Addition
		
		// DGK Test Multiplication
		
		// Division Protocol Test
		
		// Comparison Protocol Test
	
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
