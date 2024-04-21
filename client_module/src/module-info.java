module client_module {
	requires tls_module;
	requires javafx.base;
	requires transitive javafx.controls;
	requires javafx.fxml;
	requires transitive javafx.graphics;
	exports app to javafx.graphics;
	//exports fxml_controller to javafx.fxml;
	opens fxml_controller to javafx.fxml;
}