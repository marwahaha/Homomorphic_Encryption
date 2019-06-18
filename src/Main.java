import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;

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
		
		BigInteger D = PaillierCipher.encrypt(new BigInteger("100"), pk);
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
				yujia = new alice(alice_socket, pk, pubKey, true, null);
				
				// All answers should print true!
				// Size is 16 bits, 2^16 is the range
				/*
				 * 6-bits: 64
				 * 7-bits: 128
				 * 8-bits: 256
				 * 9-bts: 512
				 * 10-bits: 1024
				 * 11-bits: 2048
				 * 12-bits: 4096
				 * 13-bits: 8192
				 * 14-bits: 16384
				 * 15-bits: 32768
				 * 16-bits: 65536
				 * SEE WHERE PROTOCOL BREAKS GIVEN DEFAULT!
				 */
				
				// Test Protocol 3, mode doesn't matter as DGK is always used!
				System.out.println("Protocol 3 Tests...");
				System.out.println(yujia.Protocol3(new BigInteger("100")) == 0);//35
				System.out.println(yujia.Protocol3(new BigInteger("100")) == 1);//129
				System.out.println(yujia.Protocol3(new BigInteger("100")) == 0);//99
				System.out.println(yujia.Protocol3(new BigInteger("100")) == 1);//100
				System.out.println(yujia.Protocol3(new BigInteger("100")) == 1);//101
				
				// Test Protocol 1
				System.out.println("Protocol 1 Tests...");
				System.out.println(yujia.Protocol1(new BigInteger("100")) == 0);//35
				System.out.println(yujia.Protocol1(new BigInteger("100")) == 1);//129
				System.out.println(yujia.Protocol1(new BigInteger("100")) == 0);//99
				System.out.println(yujia.Protocol1(new BigInteger("100")) == 1);//100
				System.out.println(yujia.Protocol1(new BigInteger("100")) == 1);//101
				
				// Test Modified Protocol 3, mode doesn't matter as DGK is always used!
				System.out.println("Modified Protocol 3 Tests...");
				System.out.println(yujia.Modified_Protocol3(null, new BigInteger("100")) == 0);//35
				System.out.println(yujia.Modified_Protocol3(null, new BigInteger("100")) == 1);//129
				System.out.println(yujia.Modified_Protocol3(null, new BigInteger("100")) == 0);//99
				System.out.println(yujia.Modified_Protocol3(null, new BigInteger("100")) == 1);//100
				System.out.println(yujia.Modified_Protocol3(null, new BigInteger("100")) == 1);//101
				
				/*
				// Test Protocol 2 (Builds on Protocol 3)
				// Paillier
				System.out.println("Protocol 2 Tests...Paillier");
				yujia.setDGKMode(false);
				System.out.println(yujia.Protocol2(D, PaillierCipher.encrypt(new BigInteger("100"), pk)) == 1);
				System.out.println(yujia.Protocol2(D, PaillierCipher.encrypt(new BigInteger("101"), pk)) == 1);
				System.out.println(yujia.Protocol2(D, PaillierCipher.encrypt(new BigInteger("102"), pk)) == 1);
				System.out.println(yujia.Protocol2(D, PaillierCipher.encrypt(new BigInteger("98"), pk)) == 0);
				System.out.println(yujia.Protocol2(D, PaillierCipher.encrypt(new BigInteger("35"), pk)) == 0);
				
				// DGK
				System.out.println("Protocol 2 Tests...DGK");
				yujia.setDGKMode(true);
				System.out.println(yujia.Protocol2(d, DGKOperations.encrypt(pubKey, new BigInteger("100"))) == 1);
				System.out.println(yujia.Protocol2(d, DGKOperations.encrypt(pubKey, new BigInteger("101"))) == 1);
				System.out.println(yujia.Protocol2(d, DGKOperations.encrypt(pubKey, new BigInteger("102"))) == 1);
				System.out.println(yujia.Protocol2(d, DGKOperations.encrypt(pubKey, new BigInteger("98"))) == 0);
				System.out.println(yujia.Protocol2(d, DGKOperations.encrypt(pubKey, new BigInteger("35"))) == 0);
				
				// Test Protocol 4 (Builds on Protocol 3)
				// Paillier
				System.out.println("Protocol 4 Tests...Paillier");
				yujia.setDGKMode(false);
				System.out.println(yujia.Protocol4(D, PaillierCipher.encrypt(new BigInteger("100"), pk)) == 1);
				System.out.println(yujia.Protocol4(D, PaillierCipher.encrypt(new BigInteger("101"), pk)) == 1);
				System.out.println(yujia.Protocol4(D, PaillierCipher.encrypt(new BigInteger("102"), pk)) == 1);
				System.out.println(yujia.Protocol4(D, PaillierCipher.encrypt(new BigInteger("98"), pk)) == 0);
				System.out.println(yujia.Protocol4(D, PaillierCipher.encrypt(new BigInteger("35"), pk)) == 0);
				
				// DGK
				yujia.setDGKMode(true);
				System.out.println("Protocol 4 Tests...DGK");
				System.out.println(yujia.Protocol2(d, DGKOperations.encrypt(pubKey, new BigInteger("100"))) == 1);
				System.out.println(yujia.Protocol2(d, DGKOperations.encrypt(pubKey, new BigInteger("101"))) == 1);
				System.out.println(yujia.Protocol2(d, DGKOperations.encrypt(pubKey, new BigInteger("102"))) == 1);
				System.out.println(yujia.Protocol2(d, DGKOperations.encrypt(pubKey, new BigInteger("98"))) == 0);
				System.out.println(yujia.Protocol2(d, DGKOperations.encrypt(pubKey, new BigInteger("35"))) == 0);
				
				// Division Test, Paillier
				// REMEMBER THE OUTPUT IS THE ENCRYPTED ANSWER, ONLY BOB CAN VERIFY THE ANSWER
				yujia.setDGKMode(false);
				System.out.println("Division Tests...Paillier");
				yujia.division(D, 2);//100/2 = 50
				yujia.division(D, 4);//100/4 = 25
				yujia.division(D, 5);//100/5 = 20
				yujia.division(D, 25);//100/25 = 4
				
				yujia.setDGKMode(true);
				System.out.println("Division Tests...DGK");
				yujia.division(d, 2);//100/2 = 50
				yujia.division(d, 4);//100/4 = 25
				yujia.division(d, 5);//100/5 = 20
				yujia.division(d, 25);//100/25 = 4
				*/
			}
			else
			{
				// Init
				bob_socket = new ServerSocket(9254);
				System.out.println("Bob is ready");
				bob_client = bob_socket.accept();
				Niu = new bob(bob_client, pk, sk, pubKey, privKey, true);

				// Test Protocol 3
				Niu.Protocol3(new BigInteger("35"));
				Niu.Protocol3(new BigInteger("129"));
				Niu.Protocol3(new BigInteger("99"));
				Niu.Protocol3(new BigInteger("100"));
				Niu.Protocol3(new BigInteger("101"));
				
				// Test Protocol 1
				Niu.Protocol1(new BigInteger("35"));
				Niu.Protocol1(new BigInteger("129"));
				Niu.Protocol1(new BigInteger("99"));
				Niu.Protocol1(new BigInteger("100"));
				Niu.Protocol1(new BigInteger("101"));
				
				// Test Modified Protocol 3
				Niu.Modified_Protocol3(null, new BigInteger("35"));
				Niu.Modified_Protocol3(null, new BigInteger("129"));
				Niu.Modified_Protocol3(null, new BigInteger("99"));
				Niu.Modified_Protocol3(null, new BigInteger("100"));
				Niu.Modified_Protocol3(null, new BigInteger("101"));
				
				/*
				// Test Protocol 2 with Paillier
				Niu.setDGKMode(false);
				Niu.Protocol2();
				Niu.Protocol2();
				Niu.Protocol2();
				Niu.Protocol2();
				Niu.Protocol2();
				
				// Test Procotol 2 with DGK
				Niu.setDGKMode(true);
				Niu.Protocol2();
				Niu.Protocol2();
				Niu.Protocol2();
				Niu.Protocol2();
				Niu.Protocol2();
				
				// Test Protocol 4 with Paillier
				Niu.setDGKMode(false);
				Niu.Protocol4();
				Niu.Protocol4();
				Niu.Protocol4();
				Niu.Protocol4();
				Niu.Protocol4();
				
				// Test Procotol 4 with DGK
				Niu.setDGKMode(true);
				Niu.Protocol4();
				Niu.Protocol4();
				Niu.Protocol4();
				Niu.Protocol4();
				Niu.Protocol4();
				
				// Division Protocol Test, Paillier
				Niu.setDGKMode(false);
				Niu.division(2);
				Niu.division(4);
				Niu.division(5);
				Niu.division(25);
				
				// Division Test, DGK
				Niu.setDGKMode(true);
				Niu.division(2);
				Niu.division(4);
				Niu.division(5);
				Niu.division(25);
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
