import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
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
		DGKPublicKey pubKey = (DGKPublicKey) DGK.getPublic();
		DGKPrivateKey privKey = (DGKPrivateKey) DGK.getPrivate();
		
		// Build Paillier Keys
		PaillierKeyPairGenerator p = new PaillierKeyPairGenerator();
		p.initialize(1024, null);
		KeyPair pe = p.generateKeyPair();
		PaillierPublicKey pk = (PaillierPublicKey) pe.getPublic();
		PaillierPrivateKey sk = (PaillierPrivateKey) pe.getPrivate();
		
		// Paillier Test Addition
		
		// Paillier Test Multiplication
		
		// DGK Test Addition
		
		// DGK Test Multiplication
		
		// Initialize Alice and Bob
		ServerSocket bob_socket = null;
		Socket alice_socket = null;
		Socket bob_client = null;
		bob bo = null;
		alice yujia = null;
		
		
		BigInteger D = new BigInteger("100");
		D = PaillierCipher.encrypt(D, pk);
		try
		{
			if (isAlice)
			{
				// I need to ensure that Alice has same Keys as Bob!
				// and initialize as well
				alice_socket = new Socket("192.168.147.100", 9254);
				yujia = new alice(alice_socket, pk, pubKey, false, null);
				yujia.getDGKPublicKey();
				yujia.getPaillierPublicKey();
				
				// Division Protocol Test, Paillier
				yujia.division(D, 2);
					
				// Division Test, DGK
				yujia.setDGKstatus(true);
					
					
				// Comparison Protocol Test, Paillier
				yujia.setDGKstatus(false);
				yujia.sortArray();
					
				// Comparison Test, DGK
				yujia.setDGKstatus(true);
					
				// Clean up
				alice_socket.close();
				
			}
			else
			{
				// Init
				bob_socket = new ServerSocket(9254);
				bob_client = bob_socket.accept();
				bo = new bob(bob_client, pk, sk, pubKey, privKey, false);
				bo.getDGKPublicKey();
				bo.getPaillierPublicKey();
				
				// Division Protocol Test, Paillier
				bo.division(2);
				
				// Division Test, DGK
				bo.setDGKMode(true);

				// Comparison Protocol Test, Paillier
				bo.setDGKMode(false);
				bo.repeat_Protocol2();
					
				// Comparison Test, DGK
				bo.setDGKMode(true);
				
				// Clean up
				bob_client.close();
				bob_socket.close();
			}	
		}
		catch (IOException e)
		{
			e.printStackTrace();
		}
		catch (ClassNotFoundException e) 
		{
			e.printStackTrace();
		}
	}
}
