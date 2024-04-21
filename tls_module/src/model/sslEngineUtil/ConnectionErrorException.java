package model.sslEngineUtil;

import java.io.IOException;

public class ConnectionErrorException extends IOException{
	public ConnectionErrorException(){
		super();
	}
	public ConnectionErrorException(String msg){
		super(msg);
	}
}