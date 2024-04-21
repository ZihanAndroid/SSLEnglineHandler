package model.sslEngineUtil;

import java.io.IOException;

public class ConnectionClosedException extends IOException{
	public ConnectionClosedException(){
		super();
	}
	public ConnectionClosedException(String msg){
		super(msg);
	}
}