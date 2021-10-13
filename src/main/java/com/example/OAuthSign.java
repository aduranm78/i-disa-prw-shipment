package com.example;

import java.io.IOException;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.http.client.methods.HttpPost;

import oauth.signpost.OAuthConsumer;
import oauth.signpost.commonshttp.CommonsHttpOAuthConsumer;
import oauth.signpost.exception.OAuthCommunicationException;
import oauth.signpost.exception.OAuthExpectationFailedException;
import oauth.signpost.exception.OAuthMessageSignerException;
import oauth.signpost.http.HttpRequest;
import oauth.signpost.signature.HmacSha256MessageSigner;

public class OAuthSign {
	public static String getAuthHeader(String uri) throws IOException {           
	    String consumer_key = "0f28f2f921c537a0520cd09201b9e502688c91593b7a76344cfb1e736e25f149";
		String consumer_secret = "1f5e0c3795aecacbdfc449b145c5eefa41fd326812cf9a1983812a3c224e7adf";
		String access_token = "8aff3dcbad25dac1fe82eadb77b6e11f85f95492ed4d73cb19c1c4e2169acc21";
		String access_secret= "ef68c7a53e4e96910edc6da4612c0be3e33ece360fb4da0a7fdc3df87e15d386";

	    OAuthConsumer consumer = new CommonsHttpOAuthConsumer(consumer_key, consumer_secret);
	    consumer.setMessageSigner(new HmacSha256MessageSigner());
	    consumer.setTokenWithSecret(access_token, access_secret);
	    
	    HttpPost httppost= new HttpPost(uri);
	    
	    try {
	        HttpRequest signedReq = consumer.sign(httppost);
	        String realm = "OAuth realm=\"5298967_RP\",";
	        return signedReq.getHeader("Authorization").toString().replace("OAuth", realm);
	    } catch (OAuthMessageSignerException ex) {
	        Logger.getLogger(HttpPost.class.getName()).log(Level.SEVERE, null, ex);
	        return ex.getMessage();
	    } catch (OAuthExpectationFailedException ex) {
	        Logger.getLogger(HttpPost.class.getName()).log(Level.SEVERE, null, ex);
	        return ex.getMessage();
	    } catch (OAuthCommunicationException ex) {
	        Logger.getLogger(HttpPost.class.getName()).log(Level.SEVERE, null, ex);
	        return ex.getMessage();
	    }
	    
	    // HttpParameters httpParams = consumer.getRequestParameters();
	    // Set<String> paramKeys = httpParams.keySet();
	    
	    // for (String k : paramKeys) {
	    // 	System.out.println(httpParams.getAsHeaderElement(k));
	    // }
	    // System.out.println(httpParams.getAsHeaderElement("oauth_signature"));
	}
}
