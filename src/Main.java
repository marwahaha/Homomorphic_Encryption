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
		/*
		if(args[0].equals("Niu"))
		{
			System.out.println("Alice mode activated...");
			isAlice = true;
		}
		*/
		if (args.length != 0)
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
		
		// Get your test data...
		BigInteger [] low = generate_low();
		BigInteger [] mid = generate_mid();
		BigInteger [] high = generate_high();
		
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
				alice_socket = new Socket("160.39.205.85", 9254);
				yujia = new alice(alice_socket, true);
				yujia.receiveDGKPublicKey();
				yujia.receivePaillierPublicKey();
				
				// TO BE CONSISTENT I NEED TO USE KEYS FROM BOB!
				pk = yujia.getPaiilierPublicKey();
				pubKey = yujia.getDGKPublicKey();

				// All answers should print true!
				// Size is 16 bits, 2^16 is the range
				
				// Test Protocol 3, mode doesn't matter as DGK is always used!
				System.out.println("Protocol 3 Tests...");
				for(BigInteger l: low)
				{
					System.out.println(yujia.Protocol3(l) == 1);
				}
				for(BigInteger l: mid)
				{
					System.out.println(yujia.Protocol3(l) == 1);
				}
				for(BigInteger l: high)
				{
					System.out.println(yujia.Protocol3(l) == 0);
				}
				
				// Test Protocol 1
				System.out.println("Protocol 1 Tests...");
				for(BigInteger l: low)
				{
					System.out.println(yujia.Protocol1(l) == 1);
				}
				for(BigInteger l: mid)
				{
					System.out.println(yujia.Protocol1(l) == 1);
				}
				for(BigInteger l: high)
				{
					System.out.println(yujia.Protocol1(l) == 0);
				}
				
				// Test Modified Protocol 3, mode doesn't matter as DGK is always used!
				System.out.println("Modified Protocol 3 Tests...");
				for(BigInteger l: low)
				{
					System.out.println(yujia.Modified_Protocol3(l) == 1);
				}
				for(BigInteger l: mid)
				{
					System.out.println(yujia.Modified_Protocol3(l) == 1);
				}
				for(BigInteger l: high)
				{
					System.out.println(yujia.Modified_Protocol3(l) == 0);
				}
				
				// Test Protocol 2 (Builds on Protocol 3)
				// Paillier
				System.out.println("Protocol 2 Tests...Paillier");
				yujia.setDGKMode(false);
				for (int i = 0; i < low.length;i++)
				{
					System.out.println(yujia.Protocol2(PaillierCipher.encrypt(low[i], pk), 
							PaillierCipher.encrypt(mid[i], pk)) == 1);
					System.out.println(yujia.Protocol2(PaillierCipher.encrypt(mid[i], pk), 
							PaillierCipher.encrypt(mid[i], pk)) == 1);
					System.out.println(yujia.Protocol2(PaillierCipher.encrypt(high[i], pk), 
							PaillierCipher.encrypt(mid[i], pk)) == 0);
				}
				
				// DGK
				System.out.println("Protocol 2 Tests...DGK");
				yujia.setDGKMode(true);
				for (int i = 0; i < low.length;i++)
				{
					System.out.println(yujia.Protocol2(DGKOperations.encrypt(pubKey, low[i]), 
							PaillierCipher.encrypt(mid[i], pk)) == 1);
					System.out.println(yujia.Protocol2(DGKOperations.encrypt(pubKey, mid[i]), 
							PaillierCipher.encrypt(mid[i], pk)) == 1);
					System.out.println(yujia.Protocol2(DGKOperations.encrypt(pubKey, high[i]), 
							PaillierCipher.encrypt(mid[i], pk)) == 0);
				}
			
				// Test Protocol 4 (Builds on Protocol 3)
				// Paillier
				/*
				System.out.println("Protocol 4 Tests...Paillier");
				yujia.setDGKMode(false);
				for (int i = 0; i < low.length;i++)
				{
					System.out.println(yujia.Protocol2(PaillierCipher.encrypt(low[i], pk), 
							PaillierCipher.encrypt(mid[i], pk)) == 1);
					System.out.println(yujia.Protocol2(PaillierCipher.encrypt(mid[i], pk), 
							PaillierCipher.encrypt(mid[i], pk)) == 1);
					System.out.println(yujia.Protocol2(PaillierCipher.encrypt(high[i], pk), 
							PaillierCipher.encrypt(mid[i], pk)) == 0);
				}
				
				// DGK
				yujia.setDGKMode(true);
				System.out.println("Protocol 4 Tests...DGK");
								for (int i = 0; i < low.length;i++)
				{
					System.out.println(yujia.Protocol4(DGKOperations.encrypt(pubKey, low[i]), 
							PaillierCipher.encrypt(mid[i], pk)) == 1);
					System.out.println(yujia.Protocol4(DGKOperations.encrypt(pubKey, mid[i]), 
							PaillierCipher.encrypt(mid[i], pk)) == 1);
					System.out.println(yujia.Protocol4(DGKOperations.encrypt(pubKey, high[i]), 
							PaillierCipher.encrypt(mid[i], pk)) == 0);
				}

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
				for(int i = 0; i < mid.length * 3; i++)
				{
					Niu.Protocol3(mid[i % mid.length]);
				}
				System.out.println("Finished Testing Protocol 3");

				// Test Protocol 1
				for(int i = 0; i < mid.length * 3; i++)
				{
					Niu.Protocol1(mid[i % mid.length]);
				}
				System.out.println("Finished Testing Protocol 1");

				// Test Modified Protocol 3
				for(int i = 0; i < mid.length * 3; i++)
				{
					Niu.Modified_Protocol3(mid[i % mid.length]);
				}
				System.out.println("Finished Testing Modified Protocol 3");
				
				// Test Protocol 2 with Paillier
				Niu.setDGKMode(false);
				for(int i = 0; i < mid.length * 3; i++)
				{
					Niu.Protocol2();
				}
				System.out.println("Finished Testing Protocol 2 w/ Paillier");

				
				// Test Procotol 2 with DGK
				Niu.setDGKMode(true);
				for(int i = 0; i < mid.length * 3; i++)
				{
					Niu.Protocol2();
				}
				System.out.println("Finished Testing Protocol 2 w/ DGK");
				
				/*
				// Test Protocol 4 with Paillier
				Niu.setDGKMode(false);
				for(int i = 0; i < mid.length * 3; i++)
				{
					Niu.Protocol2();
				}
				System.out.println("Finished Testing Protocol 4 w/ Paillier");
					
				// Test Procotol 4 with DGK
				Niu.setDGKMode(true);
				for(int i = 0; i < mid.length * 3; i++)
				{
					Niu.Protocol2();
				}
				
				System.out.println("Finished Testing Protocol 4 w/ DGK");
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
	}
	
	// Original low
	public static BigInteger [] generate_low()
	{
		BigInteger [] test_set = new BigInteger[12];
		test_set[0] = new BigInteger("32");
		test_set[1] = new BigInteger("64");
		test_set[2] = new BigInteger("128");
		test_set[3] = new BigInteger("256");
		test_set[4] = new BigInteger("512");
		
		test_set[5] = new BigInteger("1024");
		test_set[6] = new BigInteger("2048");
		test_set[7] = new BigInteger("4096");
		test_set[8] = new BigInteger("8192");
		test_set[9] = new BigInteger("16384");
		
		test_set[10] = new BigInteger("32768");
		test_set[11] = new BigInteger("65536");
		return test_set;
	}
	
	// Original Medium
	public static BigInteger[] generate_mid()
	{
		BigInteger [] test_set = new BigInteger[12];
		test_set[0] = new BigInteger("32");
		test_set[1] = new BigInteger("64");
		test_set[2] = new BigInteger("128");
		test_set[3] = new BigInteger("256");
		test_set[4] = new BigInteger("512");
		
		test_set[5] = new BigInteger("1024");
		test_set[6] = new BigInteger("2048");
		test_set[7] = new BigInteger("4096");
		test_set[8] = new BigInteger("8192");
		test_set[9] = new BigInteger("16384");
		
		test_set[10] = new BigInteger("32768");
		test_set[11] = new BigInteger("65536");
		
		for (BigInteger b: test_set)
		{
			b.add(new BigInteger("5"));
		}
		return test_set;
	}
	
	// Original High
	public static BigInteger[] generate_high()
	{
		BigInteger [] test_set = new BigInteger[12];
		test_set[0] = new BigInteger("32");
		test_set[1] = new BigInteger("64");
		test_set[2] = new BigInteger("128");
		test_set[3] = new BigInteger("256");
		test_set[4] = new BigInteger("512");
		
		test_set[5] = new BigInteger("1024");
		test_set[6] = new BigInteger("2048");
		test_set[7] = new BigInteger("4096");
		test_set[8] = new BigInteger("8192");
		test_set[9] = new BigInteger("16384");
		
		test_set[10] = new BigInteger("32768");
		test_set[11] = new BigInteger("65536");
		
		for (BigInteger b: test_set)
		{
			b.add(new BigInteger("10"));
		}
		return test_set;
	}
}
