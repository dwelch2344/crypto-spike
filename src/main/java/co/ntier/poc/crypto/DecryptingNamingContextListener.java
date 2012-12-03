package co.ntier.poc.crypto;


import java.security.PrivateKey;
import java.util.Iterator;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.catalina.core.NamingContextListener;
import org.apache.catalina.deploy.ContextEnvironment;
import org.apache.catalina.deploy.ContextResource;
import org.apache.catalina.deploy.ContextResourceEnvRef;

public class DecryptingNamingContextListener extends NamingContextListener {
	private static final Logger logger = Logger.getLogger(DecryptingNamingContextListener.class.getName());
	private PrivateKey privateKey;


	public DecryptingNamingContextListener(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}

	@Override
	public void addResource(ContextResource resource) {
		Iterator<?> propertyNames = resource.listProperties();
		while(propertyNames.hasNext()) {
			String name = (String)propertyNames.next();
			Object value = resource.getProperty(name);
			if(value != null && value instanceof String && ((String)value).startsWith(TomcatEncryptionUtils.CIPHER_TEXT_PREFIX)) {
				try {
					resource.setProperty(name, TomcatEncryptionUtils.decryptValue(((String)value).replace(TomcatEncryptionUtils.CIPHER_TEXT_PREFIX, ""), privateKey));
				} catch(TomcatCryptoException e) {
					logger.log(Level.SEVERE, "Error attempting to decrypt JNDI Resource '"+name+"="+(String)value+"'", e);
				}
			}
		}
		super.addResource(resource);
	}

	@Override
	public void addEnvironment(ContextEnvironment env) {
		String value = env.getValue();
		if(value != null && value.startsWith(TomcatEncryptionUtils.CIPHER_TEXT_PREFIX)) {
			try {
				env.setValue(TomcatEncryptionUtils.decryptValue(((String)value).replace(TomcatEncryptionUtils.CIPHER_TEXT_PREFIX, ""), privateKey));
			} catch(TomcatCryptoException e) {
				logger.log(Level.SEVERE, "Error attempting to decrypt JNDI Environment '"+env.getName()+"="+(String)value+"'", e);
			}
		}
		super.addEnvironment(env);
	}

	@Override
	public void addResourceEnvRef(ContextResourceEnvRef resourceEnvRef) {
		Iterator<?> propertyNames = resourceEnvRef.listProperties();
		while(propertyNames.hasNext()) {
			String name = (String)propertyNames.next();
			Object value = resourceEnvRef.getProperty(name);
			if(value != null && value instanceof String && ((String)value).startsWith(TomcatEncryptionUtils.CIPHER_TEXT_PREFIX)) {
				try {
					resourceEnvRef.setProperty(name, TomcatEncryptionUtils.decryptValue(((String)value).replace(TomcatEncryptionUtils.CIPHER_TEXT_PREFIX, ""), privateKey));
				} catch(TomcatCryptoException e) {
					logger.log(Level.SEVERE, "Error attempting to decrypt JNDI ResourceEnvRef '"+name+"="+(String)value+"'", e);
				}
			}
		}
		super.addResourceEnvRef(resourceEnvRef);
	}
}