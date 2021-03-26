import java.io.*;  
import java.net.*;  
import java.security.*;  
import java.util.*;  
  
public class HmacSignature {  
    public static String encrypt(  
                        String apiKey,  
                        String dateStamp,
                        String regionName,
                        String serviceName,
                        String stringToSign
                        ) {  
  
            //get the bytes of the keyStr  
            byte[] key = apiKey.getBytes();  
           
            byte[] kDate = encryptWithBytes(dateStamp,key);
            byte[] kRegion = encryptWithBytes(regionName,kDate);
            byte[] kService = encryptWithBytes(serviceName,kRegion);
            byte[] kSigning = encryptWithBytes("aws4_request",kService);
            byte[] kSignature = encryptWithBytes(stringToSign,kSigning);
            byte[]retBytes = kSignature;
            
  
            // The outer hash is the message signature...  
            // convert its bytes to hexadecimals.  
            char[] hexadecimals = new char[retBytes.length * 2];  
            for (int i = 0; i < retBytes.length; ++i) {  
                for (int j = 0; j < 2; ++j) {  
                    int value = (retBytes[i] >> (4 - 4 * j)) & 0xf;  
                    char base = (value < 10) ? ('0') : ('a' - 10);  
                    hexadecimals[i * 2 + j] = (char)(base + value);  
                }  
            }  
  
            // Return a hexadecimal string representation of the message signature.  
            return new String(hexadecimals);  
    }  
    
    

	/**
	 * to keep the key as bytes
	 * @param message this should be char
	 * @param key it should be bytes
	 * @return This should return bytes
	 */
	public static byte[] encryptWithBytes(  
            String message,  
            byte[]  key) {  

//get the bytes of the keyStr  
//byte[] key = keyStr.getBytes();  
// Start by getting an object to generate SHA-256 hashes with.  
MessageDigest sha256 = null;  
try {  
    sha256 = MessageDigest.getInstance("SHA-256");  
} catch (NoSuchAlgorithmException e) {  
    throw new java.lang.AssertionError(".hmacSHA256(): SHA-256 algorithm not found!");  
}  
// Hash the key if necessary to make it fit in a block (see RFC 2104).  
if (key.length > 64) {  
   sha256.update(key);  
    key = sha256.digest();  
    sha256.reset();  
}  

// Pad the key bytes to a block (see RFC 2104).  
byte block[] = new byte[64];  
for (int i = 0; i < key.length; ++i) block[i] = key[i];  
for (int i = key.length; i < block.length; ++i) block[i] = 0;  

// Calculate the inner hash, defined in RFC 2104 as  
// SHA-256(KEY ^ IPAD + MESSAGE)), where IPAD is 64 bytes of 0x36.  
for (int i = 0; i < 64; ++i) block[i] ^= 0x36;  
sha256.update(block);  
try {  
    sha256.update(message.getBytes("UTF-8"));  
} catch (UnsupportedEncodingException e) {  
    throw new java.lang.AssertionError(  
            "ITunesU.hmacSH256(): UTF-8 encoding not supported!");  
}  
byte[] hash = sha256.digest();  
sha256.reset();  

// Calculate the outer hash, defined in RFC 2104 as  
// SHA-256(KEY ^ OPAD + INNER_HASH), where OPAD is 64 bytes of 0x5c.  
for (int i = 0; i < 64; ++i) block[i] ^= (0x36 ^ 0x5c);  
sha256.update(block);  
sha256.update(hash);  
hash = sha256.digest();  
/*
// The outer hash is the message signature...  
// convert its bytes to hexadecimals.  
char[] hexadecimals = new char[hash.length * 2];  
for (int i = 0; i < hash.length; ++i) {  
    for (int j = 0; j < 2; ++j) {  
        int value = (hash[i] >> (4 - 4 * j)) & 0xf;  
        char base = (value < 10) ? ('0') : ('a' - 10);  
        hexadecimals[i * 2 + j] = (char)(base + value);  
    }  
}  
*/
// Return a hexadecimal string representation of the message signature.  
return hash;  
}  
    
    public static void main (String args[]) {
    	String ret =HmacSignature.encrypt("AWS4OnMeU+f1v6+8hQusbhTp1V8Qut6cISyYP2HYgS9M"
    											, "20181225"
    											, "us-east-1"
    											, "sqs"
    											,"AWS4-HMAC-SHA256\n" + 
    													"20181225T202842Z\n" + 
    													"20181225/us-east-1/sqs/aws4_request\n" + 
    													"122b9f91935e8ff02a6f40b517962d8b1b6cb7ad4252dfb0c9920c13122f9827");
    	System.out.println("return = "+ret);
    }
    
}
