javac -d mod/tls_module src/module-info.java src/model/sslEngineUtil/*.java

jar --create --module-version 1.0  --file lib/tls_module.jar -C mod/tls_module .

now you get "tls_module.jar" and use it

CAUTION:
	every time you call receiveBuffer(), you will get only one packet, you must guarantee that the bytes of all packets sent by genWrappedBuffer() 
are bigger than 8500KB, near 15000KB is the best, or you may miss some packets(can not receive them and make them handled by SSLEngine.unwrap() in time)