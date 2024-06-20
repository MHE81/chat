package Main;

import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.layout.AnchorPane;
import javafx.stage.Stage;

import java.io.IOException;


public class joinGameController extends GameScene{

    @FXML
    private AnchorPane anchorPane;

    @FXML
    public void show(){
        try {
            client.writer.writeUTF("Get Host Names");
            String sHostNum = client.reader.readUTF();
            int hostNum = Integer.parseInt(sHostNum);
            for(int i = 0; i < hostNum; i++){
                String hostName = client.reader.readUTF();
                display(hostName);
            }
            System.out.println(client.reader.readUTF());

        } catch (IOException exception) {
            exception.printStackTrace();
        }
    }
    public void display(String hostName) {
        Button bttn = new Button();
        bttn.setStyle("-fx-background-color: #ffd809; -fx-border-color: #000000;-fx-background-radius: 15; -fx-border-radius: 15;");
        bttn.setText(hostName);
        bttn.setAlignment(Pos.CENTER);
        anchorPane.getChildren().add(bttn);
        EventHandler<ActionEvent> event = e -> {
            try {
                client.writer.writeUTF("Set Host Name");
                client.writer.writeUTF(bttn.getText());
                client.gameRepeatNum = Integer.parseInt(client.reader.readUTF());
                bttn.setDisable(true);
                Parent gameParent = FXMLLoader.load(getClass().getResource("ShowGuestGame.fxml"));
                Scene gameScene = new Scene(gameParent);

                //this line gets the stage information
                Stage window = (Stage) ((Node) e.getSource()).getScene().getWindow();
                window.setScene(gameScene);
                window.show();

            }catch (Exception exception){
                exception.printStackTrace();
            }
        };
        // when button is pressed
        bttn.setOnAction(event);
    }

}