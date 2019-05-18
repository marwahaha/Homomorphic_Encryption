import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.util.Base64;


public class Main 
{
	public static void main(String [] args) throws NoSuchAlgorithmException, IOException
	{
		/*
		if (args.length != 2)
		{
			System.out.println("Please input server/client mode");
		}
		*/
		RSAKeyPairGenerator();
		
		// How to build your keys
		DGKPrivateKey x;
		DGKPublicKey y;
		PaillierPK a;
		PaillierSK b;
		
		// Paillier Test Addition
		
		// Paillier Test Multiplication
		
		// DGK Test Addition
		
		// DGK Test Multiplication
		
		// Division Protocol Test
		
		// Comparison Protocol Test
	
	}
	
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
}
