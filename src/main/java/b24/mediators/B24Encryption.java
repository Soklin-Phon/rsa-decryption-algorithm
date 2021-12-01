package b24.mediators;

import org.apache.synapse.MessageContext;
import org.apache.synapse.mediators.AbstractMediator;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMFactory;
import org.apache.axiom.soap.SOAPFactory;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

import javax.xml.namespace.QName;

public class B24Encryption extends AbstractMediator {
    public static String PUBLIC_KEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDScqHfGi4SS2q6DRkNMyfhzO+8/HoyzZMtDpD0x7KK2f+8Ctl9wTCJLcsAew+EaIDDOkat6R6BxSGwzHcBUtHaIslZJ/elk1bcJa8RHxyy+HnxHH/JmnBTJ1+XlRSgJxUlGtrsax5pfM2cVyylyJ/fYsfJoZ4FjKFmgGZptG1+gQIDAQAB";
	public String encrypt_str;
    private static final Log log = LogFactory.getLog(B24Encryption.class);

    //Allow access from outside class(Get and Set)
    public void setEncryptStr(String newValue) {
   	
  		encrypt_str = newValue;
    }
       
    public String getEncryptStr() {	
    	return encrypt_str;
    }
    
    public B24Encryption(){}

    public boolean mediate(MessageContext message) {
    	
    	String amount=""+message.getProperty("amount"); 
    	String merchant=""+message.getProperty("merchantId"); 	
    	String pin=""+message.getProperty("pin"); 	

    	String data = "pin="+pin+"#"+"merchant="+merchant+"#"+"amount="+amount+"";
 
    	//Get public key
        PublicKey publicKey = getPublicKey(PUBLIC_KEY);

        //Public key encryption
        byte[] encryptedBytes = encrypt(data.getBytes(), publicKey);

        encrypt_str = Base64.getEncoder().encodeToString(encryptedBytes);

        System.out.println(Base64.getEncoder().encodeToString(encryptedBytes));

        message.setProperty("encrypt_str", Base64.getEncoder().encodeToString(encryptedBytes));
        log.info(amount);
        log.info(data);

        return true;	
    }
      
    /**
     * Convert the base64 encoded public key string to a PublicKey instance
     *
     * @param publicKey
     * @return
     */
    public static PublicKey getPublicKey(String publicKey) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(publicKey.getBytes());
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
 
    public static byte[] encrypt(byte[] content, PublicKey publicKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");// java default "RSA"="RSA/ECB/PKCS1Padding"
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(content);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

}
