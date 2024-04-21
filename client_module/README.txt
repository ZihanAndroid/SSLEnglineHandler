Command Line:

javac -d mod --module-path "C:\Users\xziha\Desktop\netTest_\tls_module\lib";"C:\Users\xziha\Desktop\Java Runtime\javafx-sdk-15.0.1\lib" --add-modules tls_module,javafx.base,javafx.graphics,javafx.fxml,javafx.controls src/module-info.java src/fxml_controller/*.java src/presenter/*.java src/netClient/*.java src/app/*.java 

java --module-path mod;"C:\Users\xziha\Desktop\netTest_\tls_module\lib";"C:\Users\xziha\Desktop\Java Runtime\javafx-sdk-15.0.1\lib" --add-modules tls_module,javafx.base,javafx.graphics,javafx.fxml,javafx.controls --module client_module
