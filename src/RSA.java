import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Date;
import java.util.Random;

public class RSA {
	
	/////////////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////////////////////////////////////////////////////////////////////////////
    // Prime random numbers generation
	/////////////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////////////////////////////////////////////////////////////////////////////
	
	static Random gRandomGen = new Random();
	
	public static BigInteger generateRandomNumber(int numBits) {
		// Constructs a randomly generated BigInteger, uniformly distributed over the range 0 to (2^numBits - 1), inclusive.
		return new BigInteger(numBits, 10, gRandomGen);
	}
	
	// Test Miller-Rabin
    public static boolean testPrimeNumber(BigInteger p) {       
        // step 0
        BigInteger pMinus1 = p.subtract(BigInteger.ONE);
        // find s
        int s = 0;
        // divide by 2
        while (pMinus1.mod(BigInteger.TWO).equals(BigInteger.ZERO)) {
        	s++;
        	pMinus1 = pMinus1.divide(BigInteger.TWO);
        }
        BigInteger d = pMinus1;
        
        pMinus1 = p.subtract(BigInteger.ONE); // refresh value
        
        for (int k = 1; k < 10; k++) {
	        // step 1
	        BigInteger x = generateRandomNumber(p.bitLength() - 70);
	        
	        if (x.equals(BigInteger.ZERO) || x.equals(BigInteger.ONE) || x.equals(pMinus1)) {
	        	System.out.println("Test Miller-Rabin 1: bad number - generate one more time");
	        	continue;
	        }
	        
	        BigInteger resGcd = x.gcd(p);
	        if (!resGcd.equals(BigInteger.ONE)) {
	        	System.out.println("Test Miller-Rabin 1: number failed - not prime");
	        	return false;
	        }
	        
	        // step 2
	        BigInteger x_r = x.modPow(d, p);
	        // step 2.1
	        if (x_r.equals(BigInteger.ONE) || x_r.equals(pMinus1)) {
	        	//System.out.println("Test Miller-Rabin 2.1: number is pseudosimple : x^d = +-1(mod p)");
	        } else {
		        // step 2.2
		        for (int r = 1; r < s; r++) {
		        	x_r = x_r.modPow(BigInteger.TWO, p);
		        	
		        	if (x_r.equals(pMinus1)) {
			        	///System.out.println("Test Miller-Rabin 2.2: number is pseudosimple : x^(d*2^r) = -1(mod p)");
			        	continue;
		        	}
		        	
		        	if (x_r.equals(BigInteger.ONE)) {
		        		///System.out.println("Test Miller-Rabin 2.2: number failed - not prime, r = " + r);
		        		return false;
		        	}
		        }
		        return false;
	        }
	    
        }
        
        return true;
    }
	
	public static BigInteger generatePrimeNumber(int numBits) {
		BigInteger newRndNumber = BigInteger.TWO; // just to avoid errors - set NOT prime number 
		boolean isPrime = false;
		
		while (isPrime == false) {
			newRndNumber = generateRandomNumber(numBits);
			System.out.println("generatePrimeNumber: posible prime number " + newRndNumber.toString(16));
			isPrime = testPrimeNumber(newRndNumber);
		}
		return newRndNumber;
	}
	
	/////////////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////////////////////////////////////////////////////////////////////////////
    // RSA functions
	/////////////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////////////////////////////////////////////////////////////////////////////
	
    public static ArrayList<BigInteger> GenerateKeyPair(BigInteger p, BigInteger q) {
    	BigInteger n = p.multiply(q);
    	BigInteger funOylera = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
    	BigInteger e = BigInteger.TWO.pow(16).add(BigInteger.ONE);
    	
    	//check gcd (e, funOylera)
    	if (e.gcd(funOylera).equals(BigInteger.ONE) == false) {
    		System.out.println("GenerateKeyPair: gcd (e, funOylera) != 1 !!!!!");
    		assert 1 == 0;
    	}
    	
    	BigInteger d = e.modInverse(funOylera);
    	ArrayList<BigInteger> keys = new ArrayList<BigInteger>();
    	keys.add(n); // index 0 - public Key
    	keys.add(e); // index 1 - public Key
    	keys.add(d); // index 2 - private Key
    	return keys;
    }
    

    public static BigInteger Encrypt(BigInteger M, BigInteger pubKeyE, BigInteger n) {
        return M.modPow(pubKeyE, n);
    }

    public static BigInteger Decrypt(BigInteger C, BigInteger privKeyD, BigInteger n) {
        return C.modPow(privKeyD, n);
    }

    public static BigInteger Sign(BigInteger M, BigInteger privKeyD, BigInteger n) {
        return M.modPow(privKeyD, n);
    }

    public static boolean Verify(BigInteger S, BigInteger M, BigInteger pubKeyE, BigInteger n) {
    	BigInteger checkM = S.modPow(pubKeyE, n); 
        return checkM.equals(M);

    }

    public static ArrayList<BigInteger> SendKey(BigInteger k, BigInteger privKeyD, BigInteger n, BigInteger pubKeyE1, BigInteger n1) {
    	BigInteger S = k.modPow(privKeyD, n);
    	
    	
    	BigInteger S1 = S.modPow(pubKeyE1, n1);
    	BigInteger k1 = k.modPow(pubKeyE1, n1);
    	
    	System.out.println("SendKey: S = " + S.toString(16));
    	System.out.println("SendKey: S1 = " + S1.toString(16));
    	System.out.println("SendKey: k1 = " + k1.toString(16));
    	
    	ArrayList<BigInteger> key = new ArrayList<BigInteger>();
    	key.add(k1); // index 0 - k1
    	key.add(S1); // index 1 - S1
    	return key;
    }
    
    public static BigInteger ReceiveKey(ArrayList<BigInteger> key, BigInteger privKeyD1, BigInteger n1, BigInteger pubKeyE, BigInteger n) {    	
    	BigInteger k1 = key.get(0);
    	BigInteger S1 = key.get(1);
    	
    	BigInteger S = S1.modPow(privKeyD1, n1);
    	BigInteger k = k1.modPow(privKeyD1, n1);
    	
    	System.out.println("ReceiveKey: S = " + S.toString(16));
    	System.out.println("ReceiveKey: k = " + k.toString(16));
    	
    	// verify signature
    	BigInteger checkK = S.modPow(pubKeyE, n);
    	System.out.println("ReceiveKey: (authentication) verified k = " + checkK.toString(16));
    	if (k.equals(checkK) == false) {
    		System.out.println("ReceiveKey: k != checkK FAILED !!!");
    		// crash program here
    		assert 1 == 0;
    	}
    	return k;
    }
    
	public static void main(String[] args) {
		
		// Generate p,q, p1, q1 
		// p*q <= p1*q1
		BigInteger p = generatePrimeNumber(256);
		BigInteger q = generatePrimeNumber(256);
		BigInteger p_q_res = p.multiply(q);
		
		BigInteger p1 = generatePrimeNumber(256);
		BigInteger q1 = generatePrimeNumber(256);
		BigInteger p1_q1_res = p1.multiply(q1);
		// if p1_q1_res less than p_q_res, swap p,q with p1,q1
		if (p1_q1_res.compareTo(p_q_res) == -1) {
			// need to swap p,q and p1,q1
			BigInteger a = p;
			p = p1;
			p1 = a;
			
			a = q;
			q = q1;
			q1 = a;
		}
		p_q_res = p.multiply(q);
		p1_q1_res = p1.multiply(q1);
		System.out.println("");
		System.out.println("");
		ArrayList<BigInteger> A_keys = GenerateKeyPair(p, q);
		BigInteger A_pubKey_n = A_keys.get(0);
		BigInteger A_pubKey_e = A_keys.get(1);
		BigInteger A_privKey_d = A_keys.get(2);
		System.out.println("A: private key part: p  = " + p.toString(16));
		System.out.println("A: private key part: p  = " + q.toString(16));
		System.out.println("A: private key: d  = " + A_privKey_d.toString(16));
		System.out.println("A: public key: e  = " + A_pubKey_e.toString(16));
		System.out.println("A: public key: n  = " + A_pubKey_n.toString(16));
		
		
		System.out.println("");
		System.out.println("Test Encrypt / Decrypt");
		BigInteger A_M = new BigInteger("ABCDEFFFFFFFF", 16);
		BigInteger C = Encrypt(A_M, A_pubKey_e, A_pubKey_n);
		BigInteger A_M_dec = Decrypt(C, A_privKey_d, A_pubKey_n);
		
		System.out.println("A: original message  = " + A_M.toString(16));
		System.out.println("A: ciphertext  = " + C.toString(16));
		System.out.println("A: decrypted message  = " + A_M_dec.toString(16));
		
		
		System.out.println("");
		System.out.println("Test Sing / Verify");
		BigInteger S = Sign(A_M, A_privKey_d, A_pubKey_n);
		boolean result = Verify(S, A_M, A_pubKey_e, A_pubKey_n);
		System.out.println("A: message signature = " + S.toString(16));
		System.out.println("A: vefify signature result = " + result);
		
		System.out.println("");
		System.out.println("");
		ArrayList<BigInteger> B_keys = GenerateKeyPair(p1, q1);
		BigInteger B_pubKey_n = B_keys.get(0);
		BigInteger B_pubKey_e = B_keys.get(1);
		BigInteger B_privKey_d = B_keys.get(2);
		System.out.println("B: private key part: p  = " + p1.toString(16));
		System.out.println("B: private key part: p  = " + q1.toString(16));
		System.out.println("B: private key: d  = " + B_privKey_d.toString(16));
		System.out.println("B: public key: e  = " + B_pubKey_e.toString(16));
		System.out.println("B: public key: n  = " + B_pubKey_n.toString(16));
		
		System.out.println("");
		System.out.println("");
		System.out.println("Test SendKey / ReceiveKey");
		BigInteger A_k = new BigInteger("123456789", 16);
		System.out.println("A: select k = " + A_k.toString(16));
		ArrayList<BigInteger> A_key_pair = SendKey(A_k, A_privKey_d, A_pubKey_n, B_pubKey_e, B_pubKey_n);
		System.out.println("A: send key pair: k1 = " + A_key_pair.get(0).toString(16));
		System.out.println("A: send key pair: S1 = " + A_key_pair.get(1).toString(16));
		
		BigInteger B_k = ReceiveKey(A_key_pair, B_privKey_d, B_pubKey_n, A_pubKey_e, A_pubKey_n);
		System.out.println("B: receive key pair and find k = " + B_k.toString(16));
		
		System.out.println("A_k == B_k is " + A_k.equals(B_k));
		
		validateWithWebServer();
    }
	
	public static void validateWithWebServer() {
		System.out.println("");
		System.out.println("");
		System.out.println("Test RSA with Web Server");
		
		BigInteger p = new BigInteger("ca5d2d798a973b8e13d4b1e8e64e7343", 16); // define p to test Send/Receive key 
		BigInteger q = new BigInteger("ebf48c5a798cc37fbc8ed53a93eac2ab", 16); // define q to test Send/Receive key
		ArrayList<BigInteger> A_keys = GenerateKeyPair(p, q);
		BigInteger A_pubKey_n = A_keys.get(0);
		BigInteger A_pubKey_e = A_keys.get(1);
		BigInteger A_privKey_d = A_keys.get(2);
		System.out.println("A: private key part: p  = " + p.toString(16));
		System.out.println("A: private key part: q  = " + q.toString(16));
		System.out.println("A: private key: d  = " + A_privKey_d.toString(16));
		System.out.println("A: public key: e  = " + A_pubKey_e.toString(16));
		System.out.println("A: public key: n  = " + A_pubKey_n.toString(16));
		
		
		BigInteger WS_pubKey_n = new BigInteger("B54A92721B648DC2386DA84BEA69AF5A8C31244C2CA29519268A3C4D9117B50B", 16);
		BigInteger WS_pubKey_e = new BigInteger("10001", 16);
		System.out.println("");
		System.out.println("Web Server: public key n (Modulus) = " + WS_pubKey_n.toString(16));
		System.out.println("Web Server: public key e (Public exponent) = " + WS_pubKey_e.toString(16));
		
		System.out.println("");
		BigInteger MtoWS = new BigInteger("C0deC0ffee", 16);
		
		
		System.out.println("");
		System.out.println("Encryption");
		BigInteger A_C = Encrypt(MtoWS, A_pubKey_e, A_pubKey_n);
		System.out.println("A: M = " + MtoWS.toString(16));
		System.out.println("A: C = " + A_C.toString(16));
		
		System.out.println("");
		System.out.println("Decryption");
		BigInteger C = Encrypt(MtoWS, WS_pubKey_e, WS_pubKey_n);
		System.out.println("A: M = " + MtoWS.toString(16));
		System.out.println("A: cyphertext C  = " + C.toString(16));
		
		System.out.println("");
		System.out.println("Signature validation from Web Server");
		BigInteger WS_M = new BigInteger("c0ffee", 16);
		BigInteger WS_S = new BigInteger("7E9EF98DCCB53A9D10983C4DB50BDAD92D9D0AEB8FA2EAF9957E21332AEBF5C7", 16);
		System.out.println("WebW Server: M = " + WS_M.toString(16));
		System.out.println("Web Server: S = " + WS_S.toString(16));
		boolean result = Verify(WS_S, WS_M, WS_pubKey_e, WS_pubKey_n);
		System.out.println("A: vefify signature result = " + result);
		
		System.out.println("");
		System.out.println("Signature validation from A");
		BigInteger A_S = Sign(MtoWS, A_privKey_d, A_pubKey_n); 
		System.out.println("A: M = " + MtoWS.toString(16));
		System.out.println("A: Signature = " + A_S.toString(16));
		
		
		System.out.println("");
		System.out.println("Receive key from A");
		BigInteger A_k = new BigInteger("1ab2c0dec0ffee", 16);
		System.out.println("A: select k = " + A_k.toString(16));
		ArrayList<BigInteger> A_key_pair = SendKey(A_k, A_privKey_d, A_pubKey_n, WS_pubKey_e, WS_pubKey_n);
		System.out.println("A: send key modulus n = " + A_pubKey_n.toString(16));
		System.out.println("A: send key exponent e = " + A_pubKey_e.toString(16));
		System.out.println("A: send key pair: k1 = " + A_key_pair.get(0).toString(16));
		System.out.println("A: send key pair: S1 = " + A_key_pair.get(1).toString(16));
		
		System.out.println("");
		System.out.println("Send Key from Web Server to A");
		BigInteger WS_K1 = new BigInteger("555A3AC8FC39E69D3F31A2F4B9708032DEA33E466B155A4114DE05233905ED0F", 16);
		BigInteger WS_S1 = new BigInteger("11EF69C4F23F7A8BF77B6A0B09A14F3A3E979F6D0FD17CD765C1D67DC9C09858", 16);
		
		ArrayList<BigInteger> WS_key_pair = new ArrayList<BigInteger>();
		WS_key_pair.add(WS_K1);
		WS_key_pair.add(WS_S1);
		System.out.println("A: receive key pair K1 = " + WS_K1.toString(16));
		System.out.println("A: receive key pair S1 = " + WS_S1.toString(16));
		BigInteger WS_k = ReceiveKey(WS_key_pair, A_privKey_d, A_pubKey_n, WS_pubKey_e, WS_pubKey_n);
		System.out.println("A: find k = " + WS_k.toString(16));		
	}
}
