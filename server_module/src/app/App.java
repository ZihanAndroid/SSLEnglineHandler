package app;

import server.Server;

public class App {
	public static void main(String[] args) {
		//port: 4647
		Server server = new Server(4647);
		server.start();
	}
}
