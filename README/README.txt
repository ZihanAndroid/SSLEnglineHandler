Command-line:

keytool -genkeypair -keystore serverKeyStore/server.keystore -alias server_keyPair -keyalg rsa -keysize 4096 -validity 365

keytool -exportcert -keystore serverKeystore/server.keystore -alias server_keyPair -file serverKeystore/server.cer

keytool -genkeypair -keystore clientKeyStore/client.keystore -alias client_keyPair -keyalg rsa -keysize 4096 -validity 365

keytool -exportcert -keystore clientKeystore/client.keystore -alias client_keyPair -file clientKeystore/client.cer

keytool -importcert -keystore serverKeyStore/serverTrustedKeys.keystore -alias client_cert -file clientKeyStore/client.cer
(set new password for serverTrustedKeys.keystore)

keytool -importcert -keystore clientKeyStore/clientTrustedKeys.keystore -alias server_cert -file serverKeyStore/server.cer
(set new password for clientTrustedKeys.keystore)

keytool -import -v -trustcacerts -keystore clientKeyStore/client.keystore -alias server_ca -file serverKeyStore/server.cer
(input client.keystore password, add CA to KeyStore for KeyManager)

if the client needs to be verified by server:
	keytool -import -v -trustcacerts -keystore serverKeyStore/server.keystore -alias client_ca -file clientKeyStore/client.cer
	(input server.keystore password, add CA to KeyStore for KeyManager)

for client, there are 2 keystore:
	1.	client.keystore	=>	for KeyManager	(CA is in KeyManager or the default ca of JVM (in jdk-11.0.7_windows-x64_bin\jdk-11.0.7\lib\security\cacerts) KeyStore file)
			(1)	a keypair(public & private keys)
			(2) CA certificate to verify the certificate chain(not just certificate) in clientTrustedKeys.keystore
				(can be the same server certificate in clientTrustedKeys.keystore for self-signed server certificate)
	2.	clientTrustedKeys.keystore	=>	for TrustManager
			(1) server certificate


