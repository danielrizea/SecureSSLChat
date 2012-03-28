/**
	Tema 4 SPRC chatSSL
	@author Rizea Daniel
 */
package com.sprc.chatssl;


import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.StringTokenizer;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;


/**
* Custom Trust manager, accepts only certificates having issuer O : MyCompany
 */
class CertificateInfo{
	
	public String O = "";
	public String OU = "";
	public String CN = "";
	
}

public class EasyX509TrustManager implements X509TrustManager
{
	
    private X509TrustManager standardTrustManager = null;	
	
/* Function gets certificate info from string to object CertificateInfo
 * returns : 
 */
    public CertificateInfo getCertificateInformation(String infoString){
	
		CertificateInfo info = new CertificateInfo();
		String cer = "";
		String val = "";
		StringTokenizer st = new StringTokenizer(infoString, ",");
		//System.out.println("Here it is");
		while(st.hasMoreTokens()) {
			
		
			String token = st.nextToken();
		//	System.out.println("Tocken " + token);
			int pos = token.indexOf('=');
			
			//System.out.println("String " + pos);
			if(pos>0){
			
				
				if(token.charAt(0) == ' ')
					cer = token.substring(1,pos);
				else
					cer = token.substring(0,pos);
				
				val = token.substring(pos+1);
			//	System.out.println("Str" + cer + " " + val);
			if(cer.toLowerCase().compareTo("o") == 0){
				//System.out.println("O memorized");
				info.O = val;
			}else
				if(cer.toLowerCase().compareTo("cn") == 0){
					info.CN = val;
				//	System.out.println("CN memorized");
				}
				else
					if(cer.toLowerCase().compareTo("ou") == 0){
						info.OU = val;
					//	System.out.println("OU memorized");
					}
			}
		} 	
		return info; 
    }

/*
 * Method used to auth client on server
 * throws CertificateException if certificate Issuer O is not MyCompany
 */
@Override
public void checkClientTrusted(X509Certificate[] chain, String authType)
		throws CertificateException {
	 
	    int j;    
	    
	    
	    //verifies on this chain of certificate, if one has issuer O: != MyCompany Throw exception
	    for(j=0;j<chain.length;j++){
	    		
	      CertificateInfo certInfoSubject = getCertificateInformation(chain[j].getSubjectDN().getName());
	      CertificateInfo certInfoIssuer = getCertificateInformation(chain[j].getIssuerDN().getName());
	     
	      System.out.println("Client certificate "+(j+1)+"in chain information :");
          System.out.println("Subject : " + "CN:"+certInfoSubject.CN + " "+"O:" + certInfoSubject.O + " "+"OU:" + certInfoSubject.OU );
          System.out.println("Issuer : " + "CN:"+certInfoIssuer.CN + " O:" + certInfoIssuer.O + " "+"OU:" + certInfoIssuer.OU);
          System.out.println("  Serial number: " + chain[j].getSerialNumber());
          
          //if the certificate is not signed by company: mycompany then throw exception
          if(certInfoIssuer.O.compareToIgnoreCase("mycompany") != 0)
        	  throw new CertificateException("Certificate is not signed by MyCompany so it can't be accespted");
          
          System.out.println("");
          
	    }
	this.standardTrustManager.checkClientTrusted(chain, authType);
}

/*
 * Method used to auth server to client
 * throws CertificateException if server certificate is not signed by MyCompany ( issuer O: value different than MyCompany)  
 */
@Override
public void checkServerTrusted(X509Certificate[] chain, String authType)
			throws CertificateException {

	 if ((chain != null) ) {
        
         for (int i = 0; i < chain.length; i++) {
            // LOG.debug("X509Certificate[" + i + "]=" + certificates[i]);
         }
     }
	 
     if (chain!= null) {
    	 
    	 
         X509Certificate certificate = chain[0];
        
         CertificateInfo certInfoSubject = getCertificateInformation(certificate.getSubjectDN().getName());
	     CertificateInfo certInfoIssuer = getCertificateInformation(certificate.getIssuerDN().getName());
        
	     System.out.println("Server certificate :");
	     System.out.println("Subject CN:"+certInfoSubject.CN+ " O:"+certInfoSubject.O+" OU:" + certInfoSubject.OU );
	     System.out.println("Issuer CN:"+certInfoIssuer.CN+" O:"+certInfoIssuer.O);
	     
	     if(certInfoIssuer.O.compareToIgnoreCase("mycompany") != 0)
	    	 throw new CertificateException("Certificate is not signed by MyCompany so it can't be trusted");
	    	 
     } else {
         this.standardTrustManager.checkServerTrusted(chain, authType);
     }
	 
	} 

    /**
     * Constructor for EasyX509TrustManager.
     */
    public EasyX509TrustManager(KeyStore keystore) throws NoSuchAlgorithmException, KeyStoreException {
        super();
        TrustManagerFactory factory = TrustManagerFactory.getInstance("SunX509");
        factory.init(keystore);
        TrustManager[] trustmanagers = factory.getTrustManagers();
        if (trustmanagers.length == 0) {
            throw new NoSuchAlgorithmException("SunX509 trust manager not supported");
        }
        this.standardTrustManager = (X509TrustManager)trustmanagers[0];
    }


@Override
	public X509Certificate[] getAcceptedIssuers() {
		// TODO Auto-generated method stub
		return this.standardTrustManager.getAcceptedIssuers();
	}
}