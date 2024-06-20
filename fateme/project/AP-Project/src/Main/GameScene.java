package Main;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.stage.Stage;

public class GameScene extends Application {
    public static Client client;

    @Override
    public void start(Stage primaryStage) throws Exception{
        client = new Client(this);
        client.start();
        Parent root = FXMLLoader.load(getClass().getResource("Client.fxml"));
        primaryStage.setTitle("اسم فامیل");
        Scene scene = new Scene(root);
        primaryStage.setScene(scene);
        primaryStage.show();
    }
//    public void showMessage() {
//        Platform.runLater(new Runnable() {
//            @Override
//            public void run() {
//                try {
//                    String message = client.reader.readUTF();
//                    ShowGuestGameController showGuestGameController = new ShowGuestGameController();
//                    showGuestGameController.setMessage(message);
//                }catch (Exception exception){
//                    exception.printStackTrace();
//                }
//            }
//        });
//    }
    public static void main(String[] args) {
        launch(args);
    }

}
