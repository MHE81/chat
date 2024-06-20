package First;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

public class ClientFXUI extends Application {
    public Client client;

    @Override
    public void start(Stage stage) throws Exception{
        client = new Client(this);
        client.start();
        Parent root = FXMLLoader.load(getClass().getResource("ClientFXUI.fxml"));
        stage.setTitle("اسم فامیل");
        Scene scene = new Scene(root);
        stage.setScene(scene);
        stage.show();
    }
    public static void main(String[] args) {
        launch(args);
    }
}
