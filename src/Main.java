import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.util.ArrayList;

import security.DGK.DGKGenerator;
import security.DGK.DGKOperations;
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
	
	public static void main(String [] args)
	{
		if(args[0].equals("Niu"))
		{
			System.out.println("Alice mode activated...");
			isAlice = true;
		}
		
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
		
		// Initialize Alice and Bob
		ServerSocket bob_socket = null;
		Socket alice_socket = null;
		Socket bob_client = null;
		bob Niu = null;
		alice yujia = null;
		
		BigInteger D = new BigInteger("100");
		D = PaillierCipher.encrypt(D, pk);
		BigInteger d = DGKOperations.encrypt(pubKey, 100);

		try
		{
			// Future Reference in saving keys...
			// https://stackoverflow.com/questions/1615871/creating-an-x509-certificate-in-java-without-bouncycastle/2037663#2037663
			// https://bfo.com/blog/2011/03/08/odds_and_ends_creating_a_new_x_509_certificate/
			
			// DO NOT USE ASSERT WHEN CONDUCTING THE TESTS!!!!
			if (isAlice)
			{
				// I need to ensure that Alice has same Keys as Bob!
				// and initialize as well
				alice_socket = new Socket("192.168.147.145", 9254);
				yujia = new alice(alice_socket, pk, pubKey, false, null);
				
				// Division Protocol Test, Paillier
				System.out.println(yujia.division(D, 2).compareTo(new BigInteger("50")));//100/2 = 50
				System.out.println(yujia.division(D, 4).compareTo(new BigInteger("25")));//100/4 = 25
				System.out.println(yujia.division(D, 5).compareTo(new BigInteger("20")));//100/5 = 20
				System.out.println(yujia.division(D, 25).compareTo(new BigInteger("4")));//100/25 = 4
				
				// Division Test, DGK
				/*
				yujia.setDGKstatus(true);
				assert(yujia.division(d, 2).compareTo(new BigInteger("50")) == 0);
				assert(yujia.division(d, 4).compareTo(new BigInteger("25")) == 0);
				assert(yujia.division(d, 5).compareTo(new BigInteger("20")) == 0);
				assert(yujia.division(d, 25).compareTo(new BigInteger("4")) == 0);
				
				// Comparison Protocol Test, Paillier
				yujia.setDGKstatus(false);
				assert(yujia.Protocol3(new BigInteger("100"), 0) == 1);
				assert(yujia.Protocol3(new BigInteger("100"), 0) == 1);
				assert(yujia.Protocol3(new BigInteger("100"), 0) == 1);
				assert(yujia.Protocol3(new BigInteger("100"), 0) == 0);
				assert(yujia.Protocol3(new BigInteger("100"), 0) == 0);
				assert(yujia.Protocol2(D, PaillierCipher.encrypt(new BigInteger("100"), pk)) == 1);
				assert(yujia.Protocol2(D, PaillierCipher.encrypt(new BigInteger("101"), pk)) == 1);
				assert(yujia.Protocol2(D, PaillierCipher.encrypt(new BigInteger("102"), pk)) == 1);
				assert(yujia.Protocol2(D, PaillierCipher.encrypt(new BigInteger("98"), pk)) == 0);
				assert(yujia.Protocol2(D, PaillierCipher.encrypt(new BigInteger("35"), pk)) == 0);
				//yujia.sortArray();
					
				// Comparison Test, DGK
				yujia.setDGKstatus(true);
				assert(yujia.Protocol3(new BigInteger("100"), 0) == 1);
				assert(yujia.Protocol3(new BigInteger("100"), 0) == 1);
				assert(yujia.Protocol3(new BigInteger("100"), 0) == 1);
				assert(yujia.Protocol3(new BigInteger("100"), 0) == 0);
				assert(yujia.Protocol3(new BigInteger("100"), 0) == 0);
				*/
				// Clean up
				alice_socket.close();
			}
			else
			{
				// Init
				bob_socket = new ServerSocket(9254);
				System.out.println("Bob is ready");
				bob_client = bob_socket.accept();
				Niu = new bob(bob_client, pk, sk, pubKey, privKey, false);

				// Division Protocol Test, Paillier
				Niu.division(2);
				Niu.division(4);
				Niu.division(5);
				Niu.division(25);
				
				// Division Test, DGK
				/*
				Niu.setDGKMode(true);
				Niu.division(2);
				Niu.division(4);
				Niu.division(5);
				Niu.division(25);

				// Comparison Protocol Test, Paillier
				Niu.setDGKMode(false);
				Niu.Protocol3(new BigInteger("100"));
				Niu.Protocol3(new BigInteger("101"));
				Niu.Protocol3(new BigInteger("102"));
				Niu.Protocol3(new BigInteger("98"));
				Niu.Protocol3(new BigInteger("35"));
				Niu.Protocol2();
				Niu.Protocol2();
				Niu.Protocol2();
				Niu.Protocol2();
				Niu.Protocol2();
				
				//Niu.repeat_Protocol2();
					
				// Comparison Test, DGK
				Niu.setDGKMode(true);
				Niu.Protocol3(new BigInteger("100"));
				Niu.Protocol3(new BigInteger("101"));
				Niu.Protocol3(new BigInteger("102"));
				Niu.Protocol3(new BigInteger("98"));
				Niu.Protocol3(new BigInteger("35"));
				*/
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
		catch(Exception e)
		{
			e.printStackTrace();
		}
	}
}
